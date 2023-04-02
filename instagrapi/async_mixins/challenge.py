import json
import time
from typing import Dict

from instagrapi.exceptions import (
    ChallengeError,
    ChallengeRequired,
    ChallengeSelfieCaptcha,
    ChallengeUnknownStep,
)
from ..mixins.challenge import ChallengeResolveMixin, ChallengeChoice


class AsyncChallengeResolveMixin(ChallengeResolveMixin):
    """
    Async helpers for resolving login challenge
    """

    async def challenge_resolve(self, last_json: Dict) -> bool:
        """
        Start challenge resolve

        Returns
        -------
        bool
            A boolean value
        """
        # START GET REQUEST to challenge_url
        challenge_url = last_json["challenge"]["api_path"]
        try:
            user_id, nonce_code = challenge_url.split("/")[2:4]
            challenge_context = last_json.get("challenge", {}).get("challenge_context")
            if not challenge_context:
                challenge_context = json.dumps(
                    {
                        "step_name": "",
                        "nonce_code": nonce_code,
                        "user_id": int(user_id),
                        "is_stateless": False,
                    }
                )
            params = {
                "guid": self.uuid,
                "device_id": self.android_device_id,
                "challenge_context": challenge_context,
            }
        except ValueError:
            # not enough values to unpack (expected 2, got 1)
            params = {}
        try:
            await self._send_private_request(challenge_url[1:], params=params)
        except ChallengeRequired:
            assert self.last_json["message"] == "challenge_required", self.last_json
            return self.challenge_resolve_contact_form(challenge_url)
        return await self.challenge_resolve_simple(challenge_url)

    async def challenge_resolve_simple(self, challenge_url: str) -> bool:
        """
        Old type (through private api) challenge resolver
        Помогите нам удостовериться, что вы владеете этим аккаунтом

        Parameters
        ----------
        challenge_url : str
            Challenge URL

        Returns
        -------
        bool
            A boolean value
        """
        step_name = self.last_json.get("step_name", "")
        if step_name == "delta_login_review":
            # IT WAS ME (by GEO)
            await self._send_private_request(challenge_url, {"choice": "0"})
            return True
        elif step_name in ("verify_email", "select_verify_method"):
            if step_name == "select_verify_method":
                """
                {'step_name': 'select_verify_method',
                'step_data': {'choice': '0',
                'fb_access_token': 'None',
                'big_blue_token': 'None',
                'google_oauth_token': 'true',
                'vetted_device': 'None',
                'phone_number': '+7 *** ***-**-09',
                'email': 'x****g@y*****.com'},     <------------- choice
                'nonce_code': 'DrW8V4m5Ec',
                'user_id': 12060121299,
                'status': 'ok'}
                """
                steps = self.last_json["step_data"].keys()
                challenge_url = challenge_url[1:]
                if "email" in steps:
                    await self._send_private_request(
                        challenge_url, {"choice": ChallengeChoice.EMAIL}
                    )
                elif "phone_number" in steps:
                    await self._send_private_request(
                        challenge_url, {"choice": ChallengeChoice.SMS}
                    )
                else:
                    raise ChallengeError(
                        f'ChallengeResolve: Choice "email" or "phone_number" (sms) not available to this account {self.last_json}'
                    )
            wait_seconds = 5
            for attempt in range(24):
                code = self.challenge_code_handler(self.username, ChallengeChoice.EMAIL)
                if code:
                    break
                time.sleep(wait_seconds)
            print(
                f'Code entered "{code}" for {self.username} ({attempt} attempts by {wait_seconds} seconds)'
            )
            await self._send_private_request(challenge_url, {"security_code": code})
            # assert 'logged_in_user' in client.last_json
            assert self.last_json.get("action", "") == "close"
            assert self.last_json.get("status", "") == "ok"
            return True
        elif step_name == "":
            print(self.last_json)
            assert self.last_json.get("action", "") == "close"
            assert self.last_json.get("status", "") == "ok"
            return True
        elif step_name == "change_password":
            # Example: {'step_name': 'change_password',
            #  'step_data': {'new_password1': 'None', 'new_password2': 'None'},
            #  'flow_render_type': 3,
            #  'bloks_action': 'com.instagram.challenge.navigation.take_challenge',
            #  'cni': 18226879502000588,
            #  'challenge_context': '{"step_name": "change_password", "cni": 18226879502000588, "is_stateless": false, "challenge_type_enum": "PASSWORD_RESET"}',
            #  'challenge_type_enum_str': 'PASSWORD_RESET',
            #  'status': 'ok'}
            wait_seconds = 5
            for attempt in range(24):
                pwd = self.change_password_handler(self.username)
                if pwd:
                    break
                time.sleep(wait_seconds)
            print(
                f'Password entered "{pwd}" for {self.username} ({attempt} attempts by {wait_seconds} seconds)'
            )
            return self.bloks_change_password(pwd, self.last_json["challenge_context"])
        elif step_name == "selfie_captcha":
            raise ChallengeSelfieCaptcha(self.last_json)
        else:
            raise ChallengeUnknownStep(
                f'ChallengeResolve: Unknown step_name "{step_name}" for "{self.username}" in challenge resolver: {self.last_json}'
            )
        return True

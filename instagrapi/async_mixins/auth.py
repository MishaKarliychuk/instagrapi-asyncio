import base64

# import datetime
import hashlib
import hmac
import json
import random
import re
import time
import uuid
from pathlib import Path
from typing import Dict, List
from uuid import uuid4

import requests
from httpx import Cookies
from pydantic import ValidationError

from instagrapi import config
from instagrapi.exceptions import (
    ClientThrottledError,
    PleaseWaitFewMinutes,
    PrivateError,
    ReloginAttemptExceeded,
    TwoFactorRequired,
)
from instagrapi.utils import dumps, gen_token, generate_jazoest

from ..mixins.auth import PreLoginFlowMixin, PostLoginFlowMixin, LoginMixin


class AsyncPreLoginFlowMixin(PreLoginFlowMixin):
    """
    Helpers for pre login flow
    """

    async def pre_login_flow(self) -> bool:
        """
        Emulation mobile app behavior before login

        Returns
        -------
        bool
            A boolean value
        """
        # self.set_contact_point_prefill("prefill")
        # self.get_prefill_candidates(True)
        await self.set_contact_point_prefill("prefill")
        await self.sync_launcher(True)
        # self.sync_device_features(True)
        return True

    async def get_prefill_candidates(self, login: bool = False) -> Dict:
        """
        Get prefill candidates value from Instagram

        Parameters
        ----------
        login: bool, optional
            Whether to login or not

        Returns
        -------
        bool
            A boolean value
        """
        data = {
            "android_device_id": self.android_device_id,
            "client_contact_points": '[{"type":"omnistring","value":"%s","source":"last_login_attempt"}]'
            % self.username,
            "phone_id": self.phone_id,
            "usages": '["account_recovery_omnibox"]',
            "logged_in_user_ids": "[]",  # "[\"123456789\",\"987654321\"]",
            "device_id": self.uuid,
        }
        # if login is False:
        data["_csrftoken"] = self.token
        return await self.private_request(
            "accounts/get_prefill_candidates/", data, login=login
        )

    async def sync_device_features(self, login: bool = False) -> Dict:
        """
        Sync device features to your Instagram account

        Parameters
        ----------
        login: bool, optional
            Whether to login or not

        Returns
        -------
        Dict
            A dictionary of response from the call
        """
        data = {
            "id": self.uuid,
            "server_config_retrieval": "1",
            # "experiments": config.LOGIN_EXPERIMENTS,
        }
        if login is False:
            data["_uuid"] = self.uuid
            data["_uid"] = self.user_id
            data["_csrftoken"] = self.token
        # headers={"X-DEVICE-ID": self.uuid}
        return await self.private_request("qe/sync/", data, login=login)

    async def sync_launcher(self, login: bool = False) -> Dict:
        """
        Sync Launcher

        Parameters
        ----------
        login: bool, optional
            Whether to login or not

        Returns
        -------
        Dict
            A dictionary of response from the call
        """
        data = {
            "id": self.uuid,
            "server_config_retrieval": "1",
        }
        if login is False:
            data["_uid"] = self.user_id
            data["_uuid"] = self.uuid
            data["_csrftoken"] = self.token
        return await self.private_request("launcher/sync/", data, login=login)

    async def set_contact_point_prefill(self, usage: str = "prefill") -> Dict:
        """
        Sync Launcher

        Parameters
        ----------
        usage: str, optional
            Default "prefill"

        Returns
        -------
        Dict
            A dictionary of response from the call
        """
        data = {
            "phone_id": self.phone_id,
            "usage": usage,
            # "_csrftoken": self.token
        }
        return await self.private_request("accounts/contact_point_prefill/", data, login=True)


class AsyncPostLoginFlowMixin(PostLoginFlowMixin):
    """
    Helpers for post login flow
    """

    async def login_flow(self) -> bool:
        """
        Emulation mobile app behaivor after login

        Returns
        -------
        bool
            A boolean value
        """
        check_flow = []
        # chance = random.randint(1, 100) % 2 == 0
        # reason = "pull_to_refresh" if chance else "cold_start"
        check_flow.append(await self.get_reels_tray_feed("cold_start"))
        check_flow.append(await self.get_timeline_feed(["cold_start_fetch"]))
        return all(check_flow)

    async def get_timeline_feed(self, options: List[Dict] = ["pull_to_refresh"]) -> Dict:
        """
        Get your timeline feed

        Parameters
        ----------
        options: List, optional
            Configurable options

        Returns
        -------
        Dict
            A dictionary of response from the call
        """
        headers = {
            "X-Ads-Opt-Out": "0",
            "X-DEVICE-ID": self.uuid,
            "X-CM-Bandwidth-KBPS": "-1.000",  # str(random.randint(2000, 5000)),
            "X-CM-Latency": str(random.randint(1, 5)),
        }
        data = {
            "feed_view_info": "[]",  # e.g. [{"media_id":"2634223601739446191_7450075998","version":24,"media_pct":1.0,"time_info":{"10":63124,"25":63124,"50":63124,"75":63124},"latest_timestamp":1628253523186}]
            "phone_id": self.phone_id,
            "battery_level": random.randint(25, 100),
            "timezone_offset": str(self.timezone_offset),
            "_csrftoken": self.token,
            "device_id": self.uuid,
            "request_id": self.request_id,
            "_uuid": self.uuid,
            "is_charging": random.randint(0, 1),
            "will_sound_on": random.randint(0, 1),
            "session_id": self.client_session_id,
            "bloks_versioning_id": self.bloks_versioning_id,
        }
        if "pull_to_refresh" in options:
            data["reason"] = "pull_to_refresh"
            data["is_pull_to_refresh"] = "1"
        elif "cold_start_fetch" in options:
            data["reason"] = "cold_start_fetch"
            data["is_pull_to_refresh"] = "0"
        # if "push_disabled" in options:
        #     data["push_disabled"] = "true"
        # if "recovered_from_crash" in options:
        #     data["recovered_from_crash"] = "1"
        return await self.private_request(
            "feed/timeline/", json.dumps(data), with_signature=False, headers=headers
        )

    async def get_reels_tray_feed(self, reason: str = "pull_to_refresh") -> Dict:
        """
        Get your reels tray feed

        Parameters
        ----------
        reason: str, optional
            Default "pull_to_refresh"

        Returns
        -------
        Dict
            A dictionary of response from the call
        """
        data = {
            "supported_capabilities_new": config.SUPPORTED_CAPABILITIES,
            "reason": reason,
            "timezone_offset": str(self.timezone_offset),
            "tray_session_id": self.tray_session_id,
            "request_id": self.request_id,
            "latest_preloaded_reel_ids": "[]",  # [{"reel_id":"6009504750","media_count":"15","timestamp":1628253494,"media_ids":"[\"2634301737009283814\",\"2634301789371018685\",\"2634301853921370532\",\"2634301920174570551\",\"2634301973895112725\",\"2634302037581608844\",\"2634302088273817272\",\"2634302822117736694\",\"2634303181452199341\",\"2634303245482345741\",\"2634303317473473894\",\"2634303382971517344\",\"2634303441062726263\",\"2634303502039423893\",\"2634303754729475501\"]"},{"reel_id":"4357392188","media_count":"4","timestamp":1628250613,"media_ids":"[\"2634142331579781054\",\"2634142839803515356\",\"2634150786575125861\",\"2634279566740346641\"]"},{"reel_id":"5931631205","media_count":"7","timestamp":1628253023,"media_ids":"[\"2633699694927154768\",\"2634153361241413763\",\"2634196788830183839\",\"2634219197377323622\",\"2634294221109889541\",\"2634299705648894876\",\"2634299760434939842\"]"}],
            "page_size": 50,
            # "_csrftoken": self.token,
            "_uuid": self.uuid,
        }
        return await self.private_request("feed/reels_tray/", data)


class AsyncLoginMixin(AsyncPreLoginFlowMixin, AsyncPostLoginFlowMixin, LoginMixin):

    async def login_by_sessionid(self, sessionid: str) -> bool:
        """
        Login using session id

        Parameters
        ----------
        sessionid: str
            Session ID

        Returns
        -------
        bool
            A boolean value
        """
        assert isinstance(sessionid, str) and len(sessionid) > 30, "Invalid sessionid"
        self.settings["cookies"] = {"sessionid": sessionid}
        self.init()
        user_id = re.search(r"^\d+", sessionid).group()
        self.authorization_data = {
            "ds_user_id": user_id,
            "sessionid": sessionid,
            "should_use_header_over_cookies": True,
        }
        try:
            user = await self.user_info_v1(int(user_id))
        except (PrivateError, ValidationError):
            user = await self.user_short_gql(int(user_id))
        self.username = user.username
        self.cookie_dict["ds_user_id"] = user.pk
        return True

    async def login(
        self,
        username: str,
        password: str,
        relogin: bool = False,
        verification_code: str = "",
    ) -> bool:
        """
        Login

        Parameters
        ----------
        username: str
            Instagram Username
        password: str
            Instagram Password
        relogin: bool
            Whether or not to re login, default False
        verification_code: str
            2FA verification code

        Returns
        -------
        bool
            A boolean value
        """
        self.username = username
        self.password = password
        if relogin:
            self.private.cookies.clear()
            if self.relogin_attempt > 1:
                raise ReloginAttemptExceeded()
            self.relogin_attempt += 1
        # if self.user_id and self.last_login:
        #     if time.time() - self.last_login < 60 * 60 * 24:
        #        return True  # already login
        if self.user_id and not relogin:
            return True  # already login
        try:
            await self.pre_login_flow()
        except (PleaseWaitFewMinutes, ClientThrottledError):
            self.logger.warning("Ignore 429: Continue login")
            # The instagram application ignores this error
            # and continues to log in (repeat this behavior)
        enc_password = await self.password_encrypt(password)
        data = {
            "jazoest": generate_jazoest(self.phone_id),
            "country_codes": '[{"country_code":"%d","source":["default"]}]'
            % int(self.country_code),
            "phone_id": self.phone_id,
            "enc_password": enc_password,
            "username": username,
            "adid": self.advertising_id,
            "guid": self.uuid,
            "device_id": self.android_device_id,
            "google_tokens": "[]",
            "login_attempt_count": "0",
        }
        try:
            logged = await self.private_request("accounts/login/", data, login=True)
            self.authorization_data = self.parse_authorization(
                self.last_response.headers.get("ig-set-authorization")
            )
        except TwoFactorRequired as e:
            if not verification_code.strip():
                raise TwoFactorRequired(
                    f"{e} (you did not provide verification_code for login method)"
                )
            two_factor_identifier = self.last_json.get("two_factor_info", {}).get(
                "two_factor_identifier"
            )
            data = {
                "verification_code": verification_code,
                "phone_id": self.phone_id,
                "_csrftoken": self.token,
                "two_factor_identifier": two_factor_identifier,
                "username": username,
                "trust_this_device": "0",
                "guid": self.uuid,
                "device_id": self.android_device_id,
                "waterfall_id": str(uuid4()),
                "verification_method": "3",
            }
            logged = await self.private_request(
                "accounts/two_factor_login/", data, login=True
            )
            self.authorization_data = self.parse_authorization(
                self.last_response.headers.get("ig-set-authorization")
            )
        if logged:
            await self.login_flow()
            self.last_login = time.time()
            return True
        return False

    async def one_tap_app_login(self, user_id: int, nonce: str) -> bool:
        """One tap login emulation

        Parameters
        ----------
        user_id: int
            User ID
        nonce: str
            Login nonce (from Instagram, e.g. in /logout/)

        Returns
        -------
        bool
            A boolean value
        """
        user_id = int(user_id)
        data = {
            "phone_id": self.phone_id,
            "user_id": user_id,
            "adid": self.advertising_id,
            "guid": self.uuid,
            "device_id": self.uuid,
            "login_nonce": nonce,
            "_csrftoken": self.token,
        }
        return await self.private_request("accounts/one_tap_app_login/", data)

    async def relogin(self) -> bool:
        """
        Relogin helper

        Returns
        -------
        bool
            A boolean value
        """
        return await self.login(self.username, self.password, relogin=True)


    async def logout(self) -> bool:
        result = await self.private_request("accounts/logout/", {"one_tap_app_login": True})
        return result["status"] == "ok"

    @property
    def cookie_dict(self) -> dict:
        self.private.cookies: Cookies
        return dict(self.private.cookies.items())

    async def expose(self) -> Dict:
        """
        Helper to expose

        Returns
        -------
        Dict
            A dictionary of response from the call
        """
        data = {"id": self.uuid, "experiment": "ig_android_profile_contextual_feed"}
        return await self.private_request("qe/expose/", self.with_default_data(data))

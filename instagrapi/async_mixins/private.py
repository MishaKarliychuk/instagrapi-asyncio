import json
import logging
import random
import time
from json.decoder import JSONDecodeError

import requests

from instagrapi import config
from instagrapi.exceptions import (
    BadPassword,
    ChallengeRequired,
    ClientBadRequestError,
    ClientConnectionError,
    ClientError,
    ClientForbiddenError,
    ClientJSONDecodeError,
    ClientNotFoundError,
    ClientRequestTimeout,
    ClientThrottledError,
    FeedbackRequired,
    LoginRequired,
    PleaseWaitFewMinutes,
    RateLimitError,
    SentryBlock,
    TwoFactorRequired,
    UnknownError,
    VideoTooLongException,
)
from instagrapi.utils import dumps, generate_signature, random_delay

from ..mixins.private import manual_input_code, manual_change_password, PrivateRequestMixin
import httpx


class AsyncPrivateRequestMixin(PrivateRequestMixin):
    """
    Async helpers for private request
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.private = httpx.AsyncClient(verify=False, timeout=180)

    @property
    def base_headers(self):
        headers = super().base_headers
        for k, v in list(headers.items()):
            if v is None:
                del headers[k]
        return headers

    async def _send_private_request(
            self,
            endpoint,
            data=None,
            params=None,
            login=False,
            with_signature=True,
            headers=None,
            extra_sig=None,
    ):
        self.last_response = None
        self.last_json = last_json = {}  # for Sentry context in traceback

        self.private.headers.update(self.base_headers)
        if headers:
            self.private.headers.update(headers)
        if not login:
            time.sleep(self.request_timeout)
        # if self.user_id and login:
        #     raise Exception(f"User already logged ({self.user_id})")
        try:
            if not endpoint.startswith("/"):
                endpoint = f"/v1/{endpoint}"

            if endpoint == "/challenge/":  # wow so hard, is it safe tho?
                endpoint = "/v1/challenge/"

            api_url = f"https://{config.API_DOMAIN}/api{endpoint}"
            if data:  # POST
                # Client.direct_answer raw dict
                # data = json.dumps(data)
                self.private.headers[
                    "Content-Type"
                ] = "application/x-www-form-urlencoded; charset=UTF-8"
                if with_signature:
                    # Client.direct_answer doesn't need a signature
                    data = generate_signature(dumps(data))
                    if extra_sig:
                        data += "&".join(extra_sig)
                response = await self.private.post(api_url, data=data, params=params)
            else:  # GET
                self.private.headers.pop("Content-Type", None)
                response = await self.private.get(api_url, params=params)
            self.logger.debug(
                "private_request %s: %s (%s)",
                response.status_code,
                response.url,
                response.text,
            )
            mid = response.headers.get("ig-set-x-mid")
            if mid:
                self.mid = mid
            self.request_log(response)
            self.last_response = response
            response.raise_for_status()
            # last_json - for Sentry context in traceback
            self.last_json = last_json = response.json()
            self.logger.debug("last_json %s", last_json)
        except JSONDecodeError as e:
            self.logger.error(
                "Status %s: JSONDecodeError in private_request (user_id=%s, endpoint=%s) >>> %s",
                response.status_code,
                self.user_id,
                endpoint,
                response.text,
            )
            raise ClientJSONDecodeError(
                "JSONDecodeError {0!s} while opening {1!s}".format(e, response.url),
                response=response,
            )
        except (requests.HTTPError, httpx.HTTPStatusError) as e:
            try:
                self.last_json = last_json = response.json()
            except JSONDecodeError:
                pass
            message = last_json.get("message", "")
            if e.response.status_code == 403:
                if message == "login_required":
                    raise LoginRequired(response=e.response, **last_json)
                if len(e.response.text) < 512:
                    last_json["message"] = e.response.text
                raise ClientForbiddenError(e, response=e.response, **last_json)
            elif e.response.status_code == 400:
                error_type = last_json.get("error_type")
                if message == "challenge_required":
                    raise ChallengeRequired(**last_json)
                elif message == "feedback_required":
                    raise FeedbackRequired(
                        **dict(
                            last_json,
                            message="%s: %s"
                                    % (message, last_json.get("feedback_message")),
                        )
                    )
                elif error_type == "sentry_block":
                    raise SentryBlock(**last_json)
                elif error_type == "rate_limit_error":
                    raise RateLimitError(**last_json)
                elif error_type == "bad_password":
                    raise BadPassword(**last_json)
                elif error_type == "two_factor_required":
                    if not last_json["message"]:
                        last_json["message"] = "Two-factor authentication required"
                    raise TwoFactorRequired(**last_json)
                elif "Please wait a few minutes before you try again" in message:
                    raise PleaseWaitFewMinutes(e, response=e.response, **last_json)
                elif "VideoTooLongException" in message:
                    raise VideoTooLongException(e, response=e.response, **last_json)
                elif error_type or message:
                    raise UnknownError(**last_json)
                # TODO: Handle last_json with {'message': 'counter get error', 'status': 'fail'}
                self.logger.exception(e)
                self.logger.warning(
                    "Status 400: %s",
                    message or "Empty response message. Maybe enabled Two-factor auth?",
                    )
                raise ClientBadRequestError(e, response=e.response, **last_json)
            elif e.response.status_code == 429:
                self.logger.warning("Status 429: Too many requests")
                if "Please wait a few minutes before you try again" in message:
                    raise PleaseWaitFewMinutes(e, response=e.response, **last_json)
                raise ClientThrottledError(e, response=e.response, **last_json)
            elif e.response.status_code == 404:
                self.logger.warning("Status 404: Endpoint %s does not exist", endpoint)
                raise ClientNotFoundError(e, response=e.response, **last_json)
            elif e.response.status_code == 408:
                self.logger.warning("Status 408: Request Timeout")
                raise ClientRequestTimeout(e, response=e.response, **last_json)
            raise ClientError(e, response=e.response, **last_json)
        except requests.ConnectionError as e:
            raise ClientConnectionError("{e.__class__.__name__} {e}".format(e=e))
        if last_json.get("status") == "fail":
            raise ClientError(response=response, **last_json)
        elif "error_title" in last_json:
            """Example: {
            'error_title': 'bad image input extra:{}', <-------------
            'media': {
                'device_timestamp': '1588184737203',
                'upload_id': '1588184737203'
            },
            'message': 'media_needs_reupload', <-------------
            'status': 'ok' <-------------
            }"""
            raise ClientError(response=response, **last_json)
        return last_json


    async def private_request(
            self,
            endpoint,
            data=None,
            params=None,
            login=False,
            with_signature=True,
            headers=None,
            extra_sig=None,
    ):
        if self.authorization:
            if not headers:
                headers = {}
            if "authorization" not in headers:
                headers.update({"Authorization": self.authorization})
        kwargs = dict(
            data=data,
            params=params,
            login=login,
            with_signature=with_signature,
            headers=headers,
            extra_sig=extra_sig,
        )
        try:
            if self.delay_range:
                random_delay(delay_range=self.delay_range)
            self.private_requests_count += 1
            await self._send_private_request(endpoint, **kwargs)
        except ClientRequestTimeout:
            self.logger.info(
                "Wait 60 seconds and try one more time (ClientRequestTimeout)"
            )
            time.sleep(60)
            return await self._send_private_request(endpoint, **kwargs)
        # except BadPassword as e:
        #     raise e
        except Exception as e:
            if self.handle_exception:
                self.handle_exception(self, e)
            elif isinstance(e, ChallengeRequired):
                self.challenge_resolve(self.last_json)
            else:
                raise e
            if login and self.user_id:
                # After challenge resolve return last_json
                return self.last_json
            return await self._send_private_request(endpoint, **kwargs)
        return self.last_json

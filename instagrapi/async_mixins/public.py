import json
import logging
import time

import httpx

try:
    from simplejson.errors import JSONDecodeError
except ImportError:
    from json.decoder import JSONDecodeError

import requests

from instagrapi.exceptions import (
    ClientBadRequestError,
    ClientConnectionError,
    ClientError,
    ClientForbiddenError,
    ClientGraphqlError,
    ClientIncompleteReadError,
    ClientJSONDecodeError,
    ClientLoginRequired,
    ClientNotFoundError,
    ClientThrottledError,
    GenericRequestError,
)
from instagrapi.utils import json_value, random_delay


from ..mixins.public import PublicRequestMixin


class AsyncPublicRequestMixin(PublicRequestMixin):


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.public = httpx.AsyncClient(verify=False)

    async def public_request(
        self,
        url,
        data=None,
        params=None,
        headers=None,
        return_json=False,
        retries_count=3,
        retries_timeout=2,
    ):
        kwargs = dict(
            data=data,
            params=params,
            headers=headers,
            return_json=return_json,
        )
        assert retries_count <= 10, "Retries count is too high"
        assert retries_timeout <= 600, "Retries timeout is too high"
        for iteration in range(retries_count):
            try:
                if self.delay_range:
                    random_delay(delay_range=self.delay_range)
                return await self._send_public_request(url, **kwargs)
            except (
                ClientLoginRequired,
                ClientNotFoundError,
                ClientBadRequestError,
            ) as e:
                raise e  # Stop retries
            # except JSONDecodeError as e:
            #     raise ClientJSONDecodeError(e, respones=self.last_public_response)
            except ClientError as e:
                msg = str(e)
                if all(
                    (
                        isinstance(e, ClientConnectionError),
                        "SOCKSHTTPSConnectionPool" in msg,
                        "Max retries exceeded with url" in msg,
                        "Failed to establish a new connection" in msg,
                    )
                ):
                    raise e
                if retries_count > iteration + 1:
                    time.sleep(retries_timeout)
                else:
                    raise e
                continue

    async def _send_public_request(
        self, url, data=None, params=None, headers=None, return_json=False
    ):
        self.public_requests_count += 1
        if headers:
            self.public.headers.update(headers)
        if self.request_timeout:
            time.sleep(self.request_timeout)
        try:
            if data is not None:  # POST
                response = await self.public.post(url, data=data, params=params)
            else:  # GET
                response = await self.public.get(url, params=params)

            expected_length = int(response.headers.get("Content-Length") or 0)
            actual_length = expected_length  # response.raw.tell()
            if actual_length < expected_length:
                raise ClientIncompleteReadError(
                    "Incomplete read ({} bytes read, {} more expected)".format(
                        actual_length, expected_length
                    ),
                    response=response,
                )

            self.public_request_logger.debug(
                "public_request %s: %s", response.status_code, response.url
            )

            self.public_request_logger.info(
                "[%s] %s %s",
                response.status_code,
                "POST" if data else "GET",
                response.url,
            )
            self.last_public_response = response
            response.raise_for_status()
            if return_json:
                self.last_public_json = response.json()
                return self.last_public_json
            return response.text

        except JSONDecodeError as e:
            if "/login/" in response.url:
                raise ClientLoginRequired(e, response=response)

            self.public_request_logger.error(
                "Status %s: JSONDecodeError in public_request (url=%s) >>> %s",
                response.status_code,
                response.url,
                response.text,
            )
            raise ClientJSONDecodeError(
                "JSONDecodeError {0!s} while opening {1!s}".format(e, url),
                response=response,
            )
        except (requests.HTTPError, httpx.HTTPStatusError) as e:
            if e.response.status_code == 403:
                raise ClientForbiddenError(e, response=e.response)

            if e.response.status_code == 400:
                raise ClientBadRequestError(e, response=e.response)

            if e.response.status_code == 429:
                raise ClientThrottledError(e, response=e.response)

            if e.response.status_code == 404:
                raise ClientNotFoundError(e, response=e.response)

            raise ClientError(e, response=e.response)

        except requests.ConnectionError as e:
            raise ClientConnectionError("{} {}".format(e.__class__.__name__, str(e)))

    async def public_a1_request(self, endpoint, data=None, params=None, headers=None):
        url = self.PUBLIC_API_URL + endpoint.lstrip("/")
        params = params or {}
        params.update({"__a": 1, "__d": "dis"})

        response = await self.public_request(
            url, data=data, params=params, headers=headers, return_json=True
        )
        try:
            return response["graphql"]
        except KeyError as e:
            error_type = response.get("error_type")
            if error_type == "generic_request_error":
                raise GenericRequestError(
                    json_value(response, "errors", "error", 0, default=error_type),
                    **response
                )
            raise e

    async def public_graphql_request(
        self,
        variables,
        query_hash=None,
        query_id=None,
        data=None,
        params=None,
        headers=None,
    ):
        assert query_id or query_hash, "Must provide valid one of: query_id, query_hash"
        default_params = {"variables": json.dumps(variables, separators=(",", ":"))}
        if query_id:
            default_params["query_id"] = query_id

        if query_hash:
            default_params["query_hash"] = query_hash

        if params:
            params.update(default_params)
        else:
            params = default_params

        try:
            body_json = await self.public_request(
                self.GRAPHQL_PUBLIC_API_URL,
                data=data,
                params=params,
                headers=headers,
                return_json=True,
            )

            if body_json.get("status", None) != "ok":
                raise ClientGraphqlError(
                    "Unexpected status '{}' in response. Message: '{}'".format(
                        body_json.get("status", None), body_json.get("message", None)
                    ),
                    response=body_json,
                )

            return body_json["data"]

        except ClientBadRequestError as e:
            message = None
            try:
                body_json = e.response.json()
                message = body_json.get("message", None)
            except JSONDecodeError:
                pass
            raise ClientGraphqlError(
                "Error: '{}'. Message: '{}'".format(e, message), response=e.response
            )


class TopSearchesPublicMixin:
    def top_search(self, query):
        """Anonymous IG search request"""
        url = "https://www.instagram.com/web/search/topsearch/"
        params = {
            "context": "blended",
            "query": query,
            "rank_token": 0.7763938004511706,
            "include_reel": "true",
        }
        response = self.public_request(url, params=params, return_json=True)
        return response

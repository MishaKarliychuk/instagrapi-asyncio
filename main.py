import asyncio

from instagrapi import Client
from instagrapi.async_mixins import AsyncPrivateRequestMixin, AsyncLoginMixin, AsyncPublicRequestMixin, \
    AsyncUserMixin, AsyncPasswordMixin


class MyClient(AsyncPrivateRequestMixin,
               AsyncLoginMixin,
               AsyncPublicRequestMixin,
               AsyncUserMixin,
               AsyncPasswordMixin,
               Client):
    pass


async def main():
    client = MyClient()
    is_logged = await client.login('kostiaiakovlev5673', 'i9ExTSaHxDt')
    # is_logged = await client.login_by_sessionid("58575665668%3AyM9gmlSqqfDuy0%3A18%3AAYdeBR3oRni0zQ8ATUEuIAqjyB6o7Bk6zlZM6rAXTg")
    print(is_logged)
    user_id = "6193306189"  # await client.user_id_from_username("karliychuk.m")
    print(user_id)
    # user = await client.user_info(user_id)
    # print(user)
    await client.user_follow(user_id)


if __name__ == '__main__':
    asyncio.run(main())

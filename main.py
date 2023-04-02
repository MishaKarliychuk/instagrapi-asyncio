import asyncio
import random
import threading
from pathlib import Path

import instagrapi
from instagrapi import Client, AsyncClient
from instagrapi.types import StoryMention, UserShort, StoryLink, Usertag


async def main():
    global users
    # Client().cookie_dict
    # kenneth_jacksonsg61rfvzfp:ncx6gjWr||android-da3d7561655af5f9;c2f0c62f-de22-4ad8-a8d7-86970cf1a3d9;c58888-d663-446e-9a36-7f60df12deb1;5022df4a-acad-49ab-b277-29ff5ceb8330|mid=ZB3SdAABAAGJsRAMQOkPd3-gs7i8;X-MID=ZB3SdAABAAGJsRAMQOkPd3-gs7i8;rur=NCG,58683966955,1711212285:01f796a2b5afb6b0ce073295f523d0866a9a1cef3e47edede8369f28bd3e9117b2c88661;IG-U-RUR=NCG,58683966955,1711212285:01f796a2b5afb6b0ce073295f523d0866a9a1cef3e47edede8369f28bd3e9117b2c88661;ds_user_id=58683966955;IG-U-DS-USER-ID=58683966955;IG-INTENDED-USER-ID=58683966955;sessionid=58683966955%3A1FuQ2gHeOR8SFI%3A23%3AAYcvcMbwIW2W-0xoXSph0pYG3kG-wY-lmi0xgm1tDw;Authorization=Bearer IGT:2:eyJkc191c2VyX2lkIjoiNTg2ODM5NjY5NTUiLCJzZXNzaW9uaWQiOiI1ODY4Mzk2Njk1NSUzQTFGdVEyZ0hlT1I4U0ZJJTNBMjMlM0FBWWN2Y01id0lXMlctMHhvWFNwaDBwWUcza0ctd1ktbG1pMHhnbTF0RHcifQ==;X-IG-WWW-Claim=0;||

    client = AsyncClient('ronald.jacksonouj554oi', 'vUGa7ogTw3R', settings={})
    # await client.media_comments()
    # client = Client()
    is_logged = await client.login('kenneth_jacksonsg61rfvzfp', 'ncx6gjWr')
    # is_logged = await client.login('carlabarrett81', 'SmSFr0NJXQ')
    # is_logged = await client.login('ruthfair7', 'RzqevdqsEhs')
    # is_logged = await client.login_by_sessionid("58575665668%3AyM9gmlSqqfDuy0%3A18%3AAYdeBR3oRni0zQ8ATUEuIAqjyB6o7Bk6zlZM6rAXTg")
    print(is_logged)
    
    user_id = "6193306189"  # await client.user_id_from_username("annezavr") #
    print(user_id)
    # user = await client.user_info(user_id)
    # print(user)
    # await client.user_follow(user_id)
    threading.Thread(target=None)
    me_user_short = UserShort(pk=user_id, username="karliychuk.m")
    paginated_users = [users[i:i+7] for i in range(0, len(users), 7)]

    if False:
        i = 0
        paginated_users *= 10
        for us in paginated_users:
            mentions = [StoryMention(user=user, x=random.randrange(100, 1000), y=random.randrange(100, 1000), width=random.randrange(100, 1000), height=random.randrange(100, 1000))
                        for user in us]
            mentions += [StoryMention(user=me_user_short, x=random.randrange(100, 1000), y=random.randrange(100, 1000), width=random.randrange(100, 1000), height=random.randrange(100, 1000))]

            links = [StoryLink(width=0.7126011, height=0.2126011, webUri="https://chat.openai.com/chat")]
            photo = await client.photo_upload_to_story(Path("test_img.jpg"), mentions=mentions, links=links)
            print(i, photo, sep="   -->   ")
            i += 1
            await asyncio.sleep(2)

    elif True:
        paginated_users *= 10
        for us in paginated_users:
            usertags = [Usertag(user=user, x=0.6, y=0.3) for user in us]
            usertags += [Usertag(user=me_user_short, x=0.7, y=0.4)]
            usernames = [user.username for user in us]
            usernames += [me_user_short.username]
            caption = "Hi "
            for username in usernames:
                caption += f"\n@{username}"
            try:
                photo = await client.photo_upload(Path("test_img.jpg"), caption=caption, usertags=usertags)
                print(f"https://www.instagram.com/p/{photo.code}")
            except AssertionError:
                pass
            await asyncio.sleep(2)

    else:
        users += [me_user_short]
        text = "Hi it's nice site"
        for user in users:
            try:
                client.direct_send_photo(Path("test_img.jpg"), [user.pk])
                client.direct_send("https://chat.openai.com/chat", [user.pk])
            except instagrapi.exceptions.ClientForbiddenError:
                print("instagrapi.exceptions.ClientForbiddenError")

    # print(photo)
    # print(client.upload_id)

# TODO отметки в сторисах приходят в папку "Запросы", то есть пуша нет (зависит от настроек юзера)
# TODO отметки под постом приходят в раздел "Уведомления"
# TODO отметки на фото поста приходят в раздел "Уведомления"

# TODO аккаунт без прогрева может выставить 4 сторис (на каждой сторис по 8 людей отмечено) и 4 поста (на каждом посте по 8 людей отмечено НА ПОСТЕ)
# TODO аккаунт без прогрева может выставить 7 сторис (на каждой сторис по 8 людей отмечено) и 7 поста (под каждым постом по 8 людей отмечено ПОД ПОСТОМ)
# TODO аккаунт без прогрева может выставить 16+ постов, отмечая пользователей под постом (8 людей на пост)
# TODO аккаунт без прогрева может отправить 24 сообщения (также с фото) (12 людям, если по 2 сообщения) разным людям в директ

# TODO По сути 1 аккаунт может выставить 16 постов (отмечено по 8 людей под постом) и 7 сторис (отмечено по 8 людей). Всего отметок: 184

# TODO протестировать с созданием каналов в инстаграме

# TODO аккаунт с прогревом выставил 16 постов (с отметками по 8 людей под постом)
# TODO аккаунт с прогревом выставил 5 сторис (с отметками по 8 людей)

# todo по сути отметки на посте и под постом --- это тоже самое
# todo лучше всего входить через sessionid и кукисы, так как при входе по логину и паролю, может выпасть чекер подтверждения почты
# todo чтобы ввойти в аккаунт недостаточно только sessionid, нужно еще кукисы, а именно X-MID(хз), mid, ds_user_id,

if __name__ == '__main__':
    # asyncio.run(main())
    """
    client = Client()
    client.login('williamsangela816', 'x8gvwD0Vu')
    blogger_id = client.user_id_from_username("nazikone")
    print(f"{blogger_id=}")
    media = client.user_medias(blogger_id, 1)[0]
    comments = client.media_comments(media.id, amount=50)

    users = [comment.user for comment in comments]
    """

    users = [UserShort(pk='53101745308', username='esenina.blog', full_name='SMM | ТАРГЕТ | ФРІЛАНС', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/332255989_636763981544675_4563879760376261871_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=111&_nc_ohc=YQxXhCzWK30AX-02Q1g&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfA_wpb2B1qIM4AjhDYr65q8zdVz2iF4aEYOvyRGHJRTFg&oe=64133CB9&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='51540627339', username='_black.pantherr', full_name='', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/273236169_263960232539682_4171202646240246212_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=106&_nc_ohc=NVBL1fNc3YsAX-ZN9Yq&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfCvT-6BoZYRc4GGMwsU7ZHL0J0-aoPclZKlxaQaaxmwWQ&oe=64129076&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='6018354507', username='dianakononchuk8254', full_name='', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/259730280_2940135939570690_6508529058784787652_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=106&_nc_ohc=AhVYmNq665IAX-MSoNc&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfC27sCJtueGhc409ivNu_htx9NgHK6oGPGOfZ2ukbJ6_A&oe=64135460&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='8102134559', username='erika___777___', full_name='Еріка Кабацій', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/323000302_817542686008593_510655691576307520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=109&_nc_ohc=R2ioQ4f7yvcAX8KRLNX&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBouBUxOMC9K-f0CVp9S4f0neBuK5LL2b47s853fmP4-Q&oe=6412D0DC&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='28087623677', username='ritulik_', full_name='Ритулік', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/331778386_1830399857339901_91017306786454848_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=109&_nc_ohc=NwdW-vxz1RkAX_KmDcB&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfAKeZ7s2jmbWJ1HtujPJiFYwk4O5nClklDq7StzcRwR8w&oe=6411AD6C&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='7817563445', username='aaleksa.s_', full_name='sashass🕷️', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/332350156_1130789540943890_3710625676910071517_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=102&_nc_ohc=gUV_-k6wLTAAX-Gpvcj&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfC6WMaqwELvx1RkFtGvlsiAM-UGcymJS2PtK2a7a72vIQ&oe=6411CA18&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='3561089379', username='ikra_ikra_ikraaa', full_name='', profile_pic_url='https://instagram.fbom33-1.fna.fbcdn.net/v/t51.2885-19/44884218_345707102882519_2446069589734326272_n.jpg?efg=eyJybWQiOiJpZ19hbmRyb2lkX21vYmlsZV9uZXR3b3JrX3N0YWNrX3ByZXRlc3RfdjI3Mzp0aWdvbl9saWdlciJ9&_nc_ht=instagram.fbom33-1.fna.fbcdn.net&_nc_cat=1&_nc_ohc=sNZJqatCjZIAX_4zF4h&edm=ABFeTR8BAAAA&ccb=7-5&ig_cache_key=YW5vbnltb3VzX3Byb2ZpbGVfcGlj.2-ccb7-5&oh=00_AfABK6MCtb24-7h4RZ81_hSyWnb8_QhYKUmM7_I7VMbaKw&oe=6413244F&_nc_sid=93c1bc', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='38824393767', username='69ilonka96', full_name='69𝔦𝔩𝔬𝔫𝔨𝔞96♡', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/333238673_167189769412757_8834732143153294314_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=105&_nc_ohc=qB5hn8eiCZQAX9j2a4n&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfAANxV19HuciIUobVxIV0ejouUYBVvlbIUnpeu3ZzGsPA&oe=64136F8D&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46417681859', username='use_shamelese', full_name='rау★', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/334214772_1068468080735069_8992735804854322320_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=105&_nc_ohc=JbdhgjYu1VcAX-OgyWh&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfALDpCXlaXOI-l-zSXp_ndHOyJWkHgLTSqJ7wJDQ2_wDg&oe=6413055B&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='3038681306', username='y.u.l.i.a10', full_name='𝐘𝐮𝐥𝐢𝐚 𝐁𝐢𝐥𝐞𝐧𝐤𝐨', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/122084929_1078478649274615_3113937483560874795_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=107&_nc_ohc=FEhSBGliUdwAX-RiTw9&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfACC573evPP3fbvvxjkOYERCzs4N41Y6CBSxSfklgUGUg&oe=6411C99F&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='9759840993', username='martha__zh', full_name='марта', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/333026431_867271641036150_8507606667581653723_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=106&_nc_ohc=yw09OLTKYrQAX_7xcXg&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfD8DtcTJdabJMAsH7AGkB_q7KU05UQpDiB8zcsHF8oS0g&oe=641240B3&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='9759840993', username='martha__zh', full_name='марта', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/333026431_867271641036150_8507606667581653723_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=106&_nc_ohc=yw09OLTKYrQAX_7xcXg&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfD8DtcTJdabJMAsH7AGkB_q7KU05UQpDiB8zcsHF8oS0g&oe=641240B3&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='56564309766', username='_farmasi_ania_', full_name='Косметика "Фармасі"', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/317027641_857337175307536_1285654567328700436_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=104&_nc_ohc=9du7_9CulIIAX9PJeTe&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBZ7hBUlm-moWLfrzXMrR9TNroN8CLBtl9lGf4iXhbjWw&oe=64128456&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='9519360149', username='aloeeeev', full_name='', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/334305977_515141294029284_2562208087798179441_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=100&_nc_ohc=VfduIuq9JSMAX-3AHmX&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBpL1zphxD0gAFylSnO6hf_Am5x0oBkCQKwK8zsrpzseA&oe=6412C880&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='5516293281', username='antoninafedonets', full_name='Антоніна Федонець', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/332420144_1623873244728336_8021160384137003687_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=100&_nc_ohc=flGVoSrifV4AX-0GzR7&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfAQJ28y5qp0TPpg4B5DD7PQLWrXsZSzH_Se9JY4nwfmlw&oe=64138CA9&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='3662959591', username='dashahutsuliak', full_name='Гуцуляк Дарина', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/115941525_613681656227903_1554363587536992790_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=111&_nc_ohc=Ukzj-Q-1IbIAX8dNXhO&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBBWgMCjm78kn23Y2nfKoISlt6tCEfv01Z-7I0yZ4xOLA&oe=641229CC&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='50379343238', username='toma_n20_', full_name='Тома✨❤️', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/328264607_1224161151860207_8162634851705423425_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=111&_nc_ohc=CpqBQp3KoucAX83y8u3&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfA4p0qeZrMkR0Dy6BX5QonYvhYMDMZ4xRDmi-EtGtgBwQ&oe=6411B139&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='5731782161', username='bohdana_minkina', full_name='Богдана', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/234442902_371658077858266_8650009651164985366_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=110&_nc_ohc=N1Bvk3KctcwAX9PZf50&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfAwiLtbPWL2kEGGaMmqQnZLlxWMn78ecFO_J7VPW87pcA&oe=6412B4C2&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='54427223600', username='_12veronikka4_', full_name='Veronnika', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/330683584_5619594218150103_5738822197711476907_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=j0u7Re9qZs8AX-JL4Mi&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDoDXwCthhZDrHV5L-JmdC3j3i0tO0ffx1df5R0ToSyWg&oe=64121016&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='1544671949', username='ilonellee', full_name='Ilona 🕊', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320320751_698153535021820_586979427378188101_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=104&_nc_ohc=hCGPejNp7yIAX8gwuYV&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfApBjqO8XmOwQ3i0ONBRPwNKh4Rdnk5U0hv9g5wIaR9MA&oe=64132EB3&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='1976592912', username='alena.rezan', full_name='Alyona Rezan', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/275078089_3197568447227281_5385627545866260144_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=101&_nc_ohc=slkbB3Sq-7gAX9JDuPf&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBIOb1Q3ZmaLrxZ5NVaoykRbDrDknlmhbC3l01aWAIWwQ&oe=6411B98C&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='26301712960', username='_.dshik.wz._', full_name='\U0001faf6', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/290504329_1087151605222063_76163271658879838_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=107&_nc_ohc=LwrsnweaF_UAX9yTgsK&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDuSg71gYL-cVTDFASjOrdZY5BUoSWkHnx_qPyqC6ZA8A&oe=64122201&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='44810194620', username='andrusivnata', full_name='𝒩𝒶𝓉𝒶 𝒜𝓃𝒹𝓇𝓊𝓈𝒾𝓋', profile_pic_url='https://instagram.flis6-1.fna.fbcdn.net/v/t51.2885-19/44884218_345707102882519_2446069589734326272_n.jpg?efg=eyJybWQiOiJpZ19hbmRyb2lkX21vYmlsZV9uZXR3b3JrX3N0YWNrX3F1aWNfYWRqdXN0X3BhY2luZ190aW1lb3V0X2JicjI6bW5zX2FkanVzdF9wYWNpbmdfdGltZW91dCJ9&_nc_ht=instagram.flis6-1.fna.fbcdn.net&_nc_cat=1&_nc_ohc=sNZJqatCjZIAX8ipXin&edm=AEF8tYYBAAAA&ccb=7-5&ig_cache_key=YW5vbnltb3VzX3Byb2ZpbGVfcGlj.2-ccb7-5&oh=00_AfCfq69bxa2x-x1k3rtecjxtyGRW-vWoH-QEXs-D3PgjVA&oe=6413244F&_nc_sid=a9513d', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='10510695432', username='iakimashko_ekaterina', full_name='Катерина_Романівна🐍🔞🇺🇦', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/332317717_1303948276819511_894740583230379400_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=111&_nc_ohc=AZkMfZdpUVAAX9_Eel_&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfCcop5yex_YmjX5118d3ZF5WDsjA_m8E2xrL82Hro31Xg&oe=64127200&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='28083660764', username='_yulia_305_', full_name='❤♚𝓳𝓾𝓵𝓲𝓪♚❤', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/300286627_781529239654006_363164753402132812_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=110&_nc_ohc=HvKdb73POUAAX8oAYIv&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfCbuIlxgiraPF7pc0VSFLXom03T1KS0t3tXnzsv9NpoCg&oe=6411C2D3&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='31743904186', username='marriqzx', full_name='Mariana Koshka', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/324698462_1011381196411639_6629147122428165670_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=107&_nc_ohc=WykUmTprPCAAX9at_q-&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDp9XEwR2nt6zNLqnlBXJt34ZMKL5jWE0TYZvUuGBnm9g&oe=6412D35E&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='47585099484', username='kamelot_hotel_kyiv', full_name='Kamelot', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/176873741_509231746757939_118712206397449607_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=111&_nc_ohc=jkvdSoFIVa8AX8yT664&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBbmtmwkSFTuLFOdVvCTT54NLSy0HeR7zmAGvmvz4-KAw&oe=64128147&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='323044042', username='julia_sk_happy', full_name='Блогер Київ Україна', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/334604290_3775319656028325_4220606353158155758_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=109&_nc_ohc=Dq8N673W8eEAX-551k0&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBj5Oe1O7bymYyz_Z3skSJ42n77BLwFB741YZp06NHYhg&oe=641211D6&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='323044042', username='julia_sk_happy', full_name='Блогер Київ Україна', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/334604290_3775319656028325_4220606353158155758_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=109&_nc_ohc=Dq8N673W8eEAX-551k0&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBj5Oe1O7bymYyz_Z3skSJ42n77BLwFB741YZp06NHYhg&oe=641211D6&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='1572529329', username='liudakravchuk', full_name='Liuda', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/320746693_5225045207596446_7558434265670777099_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=106&_nc_ohc=_cYrlHR3XXcAX9f6zRP&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfB8wukv0jv6DswLyP6lcz3NRkD0ozHV7EQj_qpvs8Z5Pw&oe=6412CF19&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='13848648577', username='gelllmas', full_name='Dianа', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/335534876_731641768364800_1635684808288393078_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=104&_nc_ohc=BuB4CT9Wj-wAX-jz1LS&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfD4YqP7e6kUgonmjRc4ePwHVtzfi4ML0LsWIahAJl4Gig&oe=6412AD59&_nc_sid=705020', profile_pic_url_hd=None, is_private=True, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='8082146841', username='_nikolcaaa_', full_name='николька!', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/331788074_526646706207657_636797168368276280_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=109&_nc_ohc=0xtnZ7OinEUAX--QbHx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDD6LVYaSx9adPu36jLO03VQdMp1DLWNtmjCKE1Mtj10Q&oe=64135203&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='8082146841', username='_nikolcaaa_', full_name='николька!', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/331788074_526646706207657_636797168368276280_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=109&_nc_ohc=0xtnZ7OinEUAX--QbHx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDD6LVYaSx9adPu36jLO03VQdMp1DLWNtmjCKE1Mtj10Q&oe=64135203&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='8082146841', username='_nikolcaaa_', full_name='николька!', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/331788074_526646706207657_636797168368276280_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=109&_nc_ohc=0xtnZ7OinEUAX--QbHx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDD6LVYaSx9adPu36jLO03VQdMp1DLWNtmjCKE1Mtj10Q&oe=64135203&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='1572529329', username='liudakravchuk', full_name='Liuda', profile_pic_url='https://instagram.flwo7-2.fna.fbcdn.net/v/t51.2885-19/320746693_5225045207596446_7558434265670777099_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-2.fna.fbcdn.net&_nc_cat=106&_nc_ohc=_cYrlHR3XXcAX9f6zRP&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfB8wukv0jv6DswLyP6lcz3NRkD0ozHV7EQj_qpvs8Z5Pw&oe=6412CF19&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='46708312426', username='nazikone', full_name='Блогер Україна / Львів', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/320996557_2338290839669571_1487086133400281520_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=3y_O2znvrgAAX9oNKQx&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfDwB7DrEV9bRIUa5kPoNpKYnhNTLXry27QXvb_-0wnC0A&oe=641297EA&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[]), UserShort(pk='10027453125', username='o.mellnyk', full_name='Olya Melnyk', profile_pic_url='https://instagram.flwo7-1.fna.fbcdn.net/v/t51.2885-19/313807273_505810554597951_991251352176007098_n.jpg?stp=dst-jpg_s150x150&_nc_ht=instagram.flwo7-1.fna.fbcdn.net&_nc_cat=103&_nc_ohc=DBIyxIV_SIsAX-Zgz32&edm=AId3EpQBAAAA&ccb=7-5&oh=00_AfBWuyPkS93bqpY19SPNBY0BnAqBV1-EQrsUu1nclbYvug&oe=64123F69&_nc_sid=705020', profile_pic_url_hd=None, is_private=False, stories=[])]
    # print(users)
    uniq_users = {}
    for user in users:
        if not uniq_users.get(user.pk):
            uniq_users[user.pk] = user
    users = list(uniq_users.values())
    asyncio.run(main())
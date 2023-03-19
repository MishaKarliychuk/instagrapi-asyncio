import random
from typing import List, Optional, Tuple

from instagrapi.exceptions import ClientError, ClientNotFoundError, MediaNotFound
from instagrapi.extractors import extract_comment
from instagrapi.types import Comment
from ..mixins.comment import CommentMixin


class AsyncCommentMixin(CommentMixin):
    """
    Async helpers for managing comments on a Media
    """

    async def media_comments(self, media_id: str, author_id: str = None, amount: int = 20) -> List[Comment]:
        """
        Get comments on a media

        Parameters
        ----------
        media_id: str
            Unique identifier of a Media
        amount: int, optional
            Maximum number of comments to return, default is 0 - Inf

        Returns
        -------
        List[Comment]
            A list of objects of Comment
        """

        # TODO: to public or private
        def get_comments():
            if result.get("comments"):
                for comment in result.get("comments"):
                    comments.append(extract_comment(comment))

        media_id = await self.media_id(media_id, author_id=author_id)
        params = None
        comments = []
        result = await self.private_request(f"media/{media_id}/comments/", params)
        get_comments()
        while (result.get("has_more_comments") and result.get("next_max_id")) or (
            result.get("has_more_headload_comments") and result.get("next_min_id")
        ):
            try:
                if result.get("has_more_comments"):
                    params = {"max_id": result.get("next_max_id")}
                else:
                    params = {"min_id": result.get("next_min_id")}
                if not (
                    result.get("next_max_id")
                    or result.get("next_min_id")
                    or result.get("comments")
                ):
                    break
                result = await self.private_request(f"media/{media_id}/comments/", params)
                get_comments()
            except ClientNotFoundError as e:
                raise MediaNotFound(e, media_id=media_id, **self.last_json)
            except ClientError as e:
                if "Media not found" in str(e):
                    raise MediaNotFound(e, media_id=media_id, **self.last_json)
                raise e
            if amount and len(comments) >= amount:
                break
        if amount:
            comments = comments[:amount]
        return comments

    async def media_comments_chunk(
        self, media_id: str, max_amount: int, author_id: str = None, min_id: str = None
    ) -> Tuple[List[Comment], str]:
        """
        Get chunk of comments on a media and end_cursor

        Parameters
        ----------
        media_id: str
            Unique identifier of a Media
        max_amount: int
            Limit number of comments to fetch, default is 100
        min_id: str, optional
            End Cursor of previous chunk that had more comments, default value is None

        Returns
        -------
        Tuple[List[Comment], str]
            A list of objects of Comment and an end_cursor
        """

        # TODO: to public or private
        def get_comments():
            if result.get("comments"):
                for comment in result.get("comments"):
                    comments.append(extract_comment(comment))

        media_id = await self.media_id(media_id, author_id)
        params = {"min_id": min_id} if min_id else None
        comments = []
        result = await self.private_request(f"media/{media_id}/comments/", params)
        get_comments()
        while result.get("has_more_headload_comments") and result.get("next_min_id"):
            try:
                params = {"min_id": result.get("next_min_id")}
                if not (result.get("next_min_id") or result.get("comments")):
                    break
                result = await self.private_request(f"media/{media_id}/comments/", params)
                get_comments()
            except ClientNotFoundError as e:
                raise MediaNotFound(e, media_id=media_id, **self.last_json)
            except ClientError as e:
                if "Media not found" in str(e):
                    raise MediaNotFound(e, media_id=media_id, **self.last_json)
                raise e
            if len(comments) >= max_amount:
                break
        return (comments, result.get("next_min_id"))

    async def media_comment(
        self, media_id: str, text: str, author_id: str = None, replied_to_comment_id: Optional[int] = None
    ) -> Comment:
        """
        Post a comment on a media

        Parameters
        ----------
        media_id: str
            Unique identifier of a Media
        text: str
            String to be posted on the media

        Returns
        -------
        Comment
            An object of Comment type
        """
        assert self.user_id, "Login required"
        media_id = await self.media_id(media_id, author_id=author_id)
        data = {
            "delivery_class": "organic",
            "feed_position": "0",
            "container_module": "self_comments_v2_feed_contextual_self_profile",  # "comments_v2",
            "user_breadcrumb": self.gen_user_breadcrumb(len(text)),
            "idempotence_token": self.generate_uuid(),
            "comment_text": text,
        }
        if replied_to_comment_id:
            data["replied_to_comment_id"] = int(replied_to_comment_id)
        result = await self.private_request(
            f"media/{media_id}/comment/",
            self.with_action_data(data),
        )
        return extract_comment(result["comment"])

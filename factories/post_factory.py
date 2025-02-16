"""
Post Factory for Connectly API.
Provides factory methods for creating different types of posts.
"""

from typing import Dict, Any, Optional
from django.contrib.auth import get_user_model
from posts.models import Post
from singletons.logger_singleton import LoggerSingleton

logger = LoggerSingleton().get_logger()


class PostFactory:
    """Factory class for creating different types of posts."""

    @staticmethod
    def create_text_post(title: str, content: str, author_id: int) -> Post:
        """
        Create a text post.
        
        Args:
            title: The post title
            content: The post content
            author_id: The ID of the post author
            
        Returns:
            The created Post instance
        """
        logger.info(f"Creating text post: {title}")
        return Post.objects.create(
            title=title,
            content=content,
            author_id=author_id,
            post_type='text'
        )

    @staticmethod
    def create_image_post(
        title: str,
        content: str,
        author_id: int,
        file_size: int,
        dimensions: Dict[str, int]
    ) -> Post:
        """
        Create an image post.
        
        Args:
            title: The post title
            content: The post content
            author_id: The ID of the post author
            file_size: Size of the image in bytes
            dimensions: Dictionary containing width and height
            
        Returns:
            The created Post instance
        """
        logger.info(f"Creating image post: {title}")
        return Post.objects.create(
            title=title,
            content=content,
            author_id=author_id,
            post_type='image',
            metadata={
                'file_size': file_size,
                'dimensions': dimensions
            }
        )

    @staticmethod
    def create_video_post(
        title: str,
        content: str,
        author_id: int,
        file_size: int,
        duration: int
    ) -> Post:
        """
        Create a video post.
        
        Args:
            title: The post title
            content: The post content
            author_id: The ID of the post author
            file_size: Size of the video in bytes
            duration: Duration of the video in seconds
            
        Returns:
            The created Post instance
        """
        logger.info(f"Creating video post: {title}")
        return Post.objects.create(
            title=title,
            content=content,
            author_id=author_id,
            post_type='video',
            metadata={
                'file_size': file_size,
                'duration': duration
            }
        )

    @staticmethod
    def create_link_post(
        title: str,
        content: str,
        author_id: int,
        url: str,
        preview_image: Optional[str] = None
    ) -> Post:
        """
        Create a link post.
        
        Args:
            title: The post title
            content: The post content
            author_id: The ID of the post author
            url: The URL being shared
            preview_image: Optional URL to a preview image
            
        Returns:
            The created Post instance
        """
        logger.info(f"Creating link post: {title}")
        metadata = {'url': url}
        if preview_image:
            metadata['preview_image'] = preview_image

        return Post.objects.create(
            title=title,
            content=content,
            author_id=author_id,
            post_type='link',
            metadata=metadata
        )

    @classmethod
    def create_post(
        cls,
        post_type: str,
        title: str,
        content: str,
        author_id: int,
        **kwargs: Any
    ) -> Post:
        """
        Factory method to create a post of any type.
        
        Args:
            post_type: The type of post to create
            title: The post title
            content: The post content
            author_id: The ID of the post author
            **kwargs: Additional arguments specific to the post type
            
        Returns:
            The created Post instance
            
        Raises:
            ValueError: If the post type is invalid or required metadata is missing
        """
        if post_type not in dict(Post.POST_TYPES):
            raise ValueError(f"Invalid post type: {post_type}")

        if post_type == 'text':
            return cls.create_text_post(title, content, author_id)
        elif post_type == 'image':
            if 'file_size' not in kwargs or 'dimensions' not in kwargs:
                raise ValueError("Image posts require file_size and dimensions")
            return cls.create_image_post(
                title, content, author_id,
                kwargs['file_size'],
                kwargs['dimensions']
            )
        elif post_type == 'video':
            if 'file_size' not in kwargs or 'duration' not in kwargs:
                raise ValueError("Video posts require file_size and duration")
            return cls.create_video_post(
                title, content, author_id,
                kwargs['file_size'],
                kwargs['duration']
            )
        elif post_type == 'link':
            if 'url' not in kwargs:
                raise ValueError("Link posts require url")
            return cls.create_link_post(
                title, content, author_id,
                kwargs['url'],
                kwargs.get('preview_image')
            )
        
        raise ValueError(f"Unsupported post type: {post_type}") 
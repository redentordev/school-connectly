from django.test import TestCase
from django.contrib.auth.models import User
from .models import Post, Comment
from factories.post_factory import PostFactory
from singletons.config_manager import ConfigManager
from singletons.logger_singleton import LoggerSingleton
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from rest_framework.authtoken.models import Token

def get_url(viewname, *args, **kwargs):
    """Helper function to get the full URL including the 'posts/' prefix."""
    url = reverse(viewname, args=args, kwargs=kwargs)
    if not url.endswith('/'):
        url = f"{url}/"
    return url  # DRF's router already includes the app prefix

class SingletonPatternsTest(TestCase):
    def test_config_manager_singleton(self):
        """Test that ConfigManager maintains single instance."""
        config1 = ConfigManager()
        config2 = ConfigManager()
        
        self.assertIs(config1, config2)
        
        # Test setting and getting values
        config1.set_setting('TEST_KEY', 'test_value')
        self.assertEqual(config2.get_setting('TEST_KEY'), 'test_value')

    def test_logger_singleton(self):
        """Test that LoggerSingleton maintains single instance."""
        logger1 = LoggerSingleton()
        logger2 = LoggerSingleton()
        
        self.assertIs(logger1, logger2)
        self.assertIs(logger1.get_logger(), logger2.get_logger())


class PostFactoryTest(TestCase):
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create(
            username='testuser',
            email='test@example.com'
        )

    def test_create_text_post(self):
        """Test creating a text post."""
        post = PostFactory.create_post(
            post_type='text',
            title='Test Text Post',
            content='This is a test post',
            author_id=self.user.id
        )
        
        self.assertEqual(post.post_type, 'text')
        self.assertEqual(post.title, 'Test Text Post')
        self.assertEqual(post.content, 'This is a test post')
        self.assertEqual(post.author.id, self.user.id)

    def test_create_image_post(self):
        """Test creating an image post."""
        post = PostFactory.create_post(
            post_type='image',
            title='Test Image Post',
            content='Image description',
            author_id=self.user.id,
            file_size=1024,
            dimensions={'width': 800, 'height': 600}
        )
        
        self.assertEqual(post.post_type, 'image')
        self.assertEqual(post.title, 'Test Image Post')
        self.assertEqual(post.metadata['file_size'], 1024)
        self.assertEqual(post.metadata['dimensions']['width'], 800)
        self.assertEqual(post.author.id, self.user.id)

    def test_create_video_post(self):
        """Test creating a video post."""
        post = PostFactory.create_post(
            post_type='video',
            title='Test Video Post',
            content='Video description',
            author_id=self.user.id,
            file_size=1024000,
            duration=120
        )
        
        self.assertEqual(post.post_type, 'video')
        self.assertEqual(post.title, 'Test Video Post')
        self.assertEqual(post.metadata['duration'], 120)
        self.assertEqual(post.author.id, self.user.id)

    def test_create_link_post(self):
        """Test creating a link post."""
        post = PostFactory.create_post(
            post_type='link',
            title='Test Link Post',
            content='Link description',
            author_id=self.user.id,
            url='https://example.com',
            preview_image='https://example.com/preview.jpg'
        )
        
        self.assertEqual(post.post_type, 'link')
        self.assertEqual(post.title, 'Test Link Post')
        self.assertEqual(post.metadata['url'], 'https://example.com')
        self.assertEqual(post.metadata['preview_image'], 'https://example.com/preview.jpg')
        self.assertEqual(post.author.id, self.user.id)

    def test_invalid_post_type(self):
        """Test that creating a post with invalid type raises ValueError."""
        with self.assertRaises(ValueError):
            PostFactory.create_post(
                post_type='invalid',
                title='Invalid Post',
                content='This should fail',
                author_id=self.user.id
            )

    def test_missing_required_metadata(self):
        """Test that missing required metadata raises ValueError."""
        with self.assertRaises(ValueError):
            PostFactory.create_post(
                post_type='image',
                title='Invalid Image Post',
                content='This should fail',
                author_id=self.user.id,
                # Missing file_size and dimensions
            )

        with self.assertRaises(ValueError):
            PostFactory.create_post(
                post_type='video',
                title='Invalid Video Post',
                content='This should fail',
                author_id=self.user.id,
                # Missing file_size and duration
            )

        with self.assertRaises(ValueError):
            PostFactory.create_post(
                post_type='link',
                title='Invalid Link Post',
                content='This should fail',
                author_id=self.user.id,
                # Missing url
            )


class UserAPITest(APITestCase):
    def setUp(self):
        # Create an admin user
        self.admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        # Create a token for the admin user
        self.admin_token = Token.objects.create(user=self.admin_user)
        
        # Create a test user
        self.test_user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Set up authentication
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token.key}')

    def test_list_users(self):
        """Test retrieving list of users"""
        url = get_url('user-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # admin user and test user

    def test_create_user(self):
        """Test creating a new user"""
        url = get_url('user-list')
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpass123'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 3)  # admin, test user, and new user
        self.assertEqual(User.objects.get(username='newuser').email, 'newuser@example.com')

    def test_get_user_detail(self):
        """Test retrieving a specific user"""
        url = get_url('user-detail', pk=self.test_user.pk)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.test_user.username)

    def test_update_user(self):
        """Test updating an existing user"""
        url = get_url('user-detail', pk=self.test_user.pk)
        data = {
            'email': 'updated@example.com'
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.test_user.refresh_from_db()
        self.assertEqual(self.test_user.email, 'updated@example.com')

    def test_delete_user(self):
        """Test deleting a user"""
        url = get_url('user-detail', pk=self.test_user.pk)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(User.objects.count(), 1)  # Only admin user remains

    def test_unauthorized_access(self):
        """Test that unauthorized users cannot access the endpoints"""
        # Remove authentication
        self.client.credentials()
        
        # Try to access user list
        url = get_url('user-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Try to access user detail
        url = get_url('user-detail', pk=self.test_user.pk)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PostAPITest(APITestCase):
    def setUp(self):
        # Create a user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        # Create token for authentication
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        # Create a test post
        self.test_post = Post.objects.create(
            title='Test Post',
            content='Test Content',
            author=self.user,
            post_type='text'
        )

    def test_list_posts(self):
        """Test retrieving list of posts"""
        url = get_url('post-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_create_text_post(self):
        """Test creating a new text post"""
        url = get_url('post-list')
        data = {
            'title': 'New Post',
            'content': 'New Content',
            'post_type': 'text'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Post.objects.count(), 2)
        self.assertEqual(Post.objects.get(title='New Post').content, 'New Content')

    def test_create_image_post(self):
        """Test creating a new image post"""
        url = get_url('post-list')
        data = {
            'title': 'Image Post',
            'content': 'Image Description',
            'post_type': 'image',
            'metadata': {
                'file_size': 1024,
                'dimensions': {'width': 800, 'height': 600}
            }
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['post_type'], 'image')

    def test_get_post_detail(self):
        """Test retrieving a specific post"""
        url = get_url('post-detail', pk=self.test_post.pk)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], self.test_post.title)

    def test_update_post(self):
        """Test updating an existing post"""
        url = get_url('post-detail', pk=self.test_post.pk)
        data = {
            'content': 'Updated Content'
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.test_post.refresh_from_db()
        self.assertEqual(self.test_post.content, 'Updated Content')

    def test_delete_post(self):
        """Test deleting a post"""
        url = get_url('post-detail', pk=self.test_post.pk)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Post.objects.count(), 0)

    def test_unauthorized_post_modification(self):
        """Test that users cannot modify other users' posts"""
        # Create another user and their post
        other_user = User.objects.create_user(
            username='other',
            email='other@example.com',
            password='otherpass123'
        )
        other_post = Post.objects.create(
            title='Other Post',
            content='Other Content',
            author=other_user,
            post_type='text'
        )
        
        # Try to update the post
        url = get_url('post-detail', pk=other_post.pk)
        response = self.client.patch(url, {'content': 'Modified'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Try to delete the post
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class CommentAPITest(APITestCase):
    def setUp(self):
        # Create a user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        # Create token for authentication
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        # Create a test post
        self.test_post = Post.objects.create(
            title='Test Post',
            content='Test Content',
            author=self.user,
            post_type='text'
        )
        
        # Create a test comment
        self.test_comment = Comment.objects.create(
            text='Test Comment',
            author=self.user,
            post=self.test_post
        )

    def test_list_comments(self):
        """Test retrieving list of comments"""
        url = get_url('comment-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_create_comment(self):
        """Test creating a new comment"""
        url = get_url('comment-list')
        data = {
            'text': 'New Comment',
            'post': self.test_post.id
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Comment.objects.count(), 2)
        self.assertEqual(Comment.objects.get(text='New Comment').author, self.user)

    def test_get_comment_detail(self):
        """Test retrieving a specific comment"""
        url = get_url('comment-detail', pk=self.test_comment.pk)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['text'], self.test_comment.text)

    def test_update_comment(self):
        """Test updating an existing comment"""
        url = get_url('comment-detail', pk=self.test_comment.pk)
        data = {
            'text': 'Updated Comment'
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.test_comment.refresh_from_db()
        self.assertEqual(self.test_comment.text, 'Updated Comment')

    def test_delete_comment(self):
        """Test deleting a comment"""
        url = get_url('comment-detail', pk=self.test_comment.pk)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Comment.objects.count(), 0)

    def test_unauthorized_comment_modification(self):
        """Test that users cannot modify other users' comments"""
        # Create another user and their comment
        other_user = User.objects.create_user(
            username='other',
            email='other@example.com',
            password='otherpass123'
        )
        other_comment = Comment.objects.create(
            text='Other Comment',
            author=other_user,
            post=self.test_post
        )
        
        # Try to update the comment
        url = get_url('comment-detail', pk=other_comment.pk)
        response = self.client.patch(url, {'text': 'Modified'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Try to delete the comment
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import Post, User
from factories.post_factory import PostFactory
from singletons.config_manager import ConfigManager
from singletons.logger_singleton import LoggerSingleton


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

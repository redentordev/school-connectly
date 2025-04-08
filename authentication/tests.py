from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch, MagicMock
from allauth.socialaccount.models import SocialAccount

class GoogleLoginTest(APITestCase):
    def setUp(self):
        # Create a test user
        self.test_user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Mock Google's user info response
        self.google_user_info = {
            'sub': '12345678901234567890',
            'email': 'google@example.com',
            'name': 'Google User',
            'given_name': 'Google',
            'family_name': 'User',
            'picture': 'https://example.com/picture.jpg'
        }
        
        # URL to test
        self.url = reverse('google-login')

    @patch('requests.get')
    def test_google_login_creates_new_user(self, mock_get):
        """Test that Google login creates a new user if none exists"""
        # Mock the response from Google
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = self.google_user_info
        mock_get.return_value = mock_response
        
        # Make the request to our endpoint
        response = self.client.post(self.url, {'access_token': 'fake_token'}, format='json')
        
        # Check that the response is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that the user was created
        self.assertTrue(User.objects.filter(email='google@example.com').exists())
        
        # Check that the social account was created
        self.assertTrue(SocialAccount.objects.filter(uid='12345678901234567890').exists())
        
        # Check that the token is returned
        self.assertIn('token', response.data)
        self.assertIn('user_id', response.data)
        self.assertEqual(response.data['email'], 'google@example.com')
        self.assertEqual(response.data['first_name'], 'Google')
        self.assertEqual(response.data['last_name'], 'User')
        self.assertEqual(response.data['picture'], 'https://example.com/picture.jpg')

    @patch('requests.get')
    def test_google_login_links_existing_user(self, mock_get):
        """Test that Google login links to an existing user with the same email"""
        # Create a user with the same email as in the Google response
        existing_user = User.objects.create_user(
            username='googleuser',
            email='google@example.com',
            password='password123'
        )
        
        # Mock the response from Google
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = self.google_user_info
        mock_get.return_value = mock_response
        
        # Make the request to our endpoint
        response = self.client.post(self.url, {'access_token': 'fake_token'}, format='json')
        
        # Check that the response is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that a new user was not created
        self.assertEqual(User.objects.filter(email='google@example.com').count(), 1)
        
        # Check that the social account was created and linked to the existing user
        social_account = SocialAccount.objects.get(uid='12345678901234567890')
        self.assertEqual(social_account.user, existing_user)
        
        # Check that the token is returned
        self.assertIn('token', response.data)
        self.assertEqual(response.data['user_id'], existing_user.id)

    @patch('requests.get')
    def test_google_login_uses_existing_social_account(self, mock_get):
        """Test that Google login uses an existing social account"""
        # Create a user
        existing_user = User.objects.create_user(
            username='socialuser',
            email='social@example.com',
            password='password123'
        )
        
        # Create a social account for the user
        social_account = SocialAccount.objects.create(
            user=existing_user,
            provider='google',
            uid='12345678901234567890',
            extra_data=self.google_user_info
        )
        
        # Update the mock Google response to match the social account
        google_info = self.google_user_info.copy()
        google_info['email'] = 'social@example.com'
        
        # Mock the response from Google
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = google_info
        mock_get.return_value = mock_response
        
        # Make the request to our endpoint
        response = self.client.post(self.url, {'access_token': 'fake_token'}, format='json')
        
        # Check that the response is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that no new user was created
        self.assertEqual(User.objects.count(), 2)  # original test user + existing user
        
        # Check that no new social account was created
        self.assertEqual(SocialAccount.objects.count(), 1)
        
        # Check that the token is returned
        self.assertIn('token', response.data)
        self.assertEqual(response.data['user_id'], existing_user.id)

    @patch('requests.get')
    def test_google_login_invalid_token(self, mock_get):
        """Test that Google login fails with an invalid token"""
        # Mock the response from Google to indicate failure
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.text = 'Invalid token'
        mock_get.return_value = mock_response
        
        # Make the request to our endpoint
        response = self.client.post(self.url, {'access_token': 'invalid_token'}, format='json')
        
        # Check that the response is an error
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    def test_google_login_missing_token(self):
        """Test that Google login fails without a token"""
        # Make the request without a token
        response = self.client.post(self.url, {}, format='json')
        
        # Check that the response is an error
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    @patch('requests.get')
    def test_google_login_missing_email(self, mock_get):
        """Test that Google login fails if the Google response doesn't include an email"""
        # Mock response missing email
        google_info = self.google_user_info.copy()
        del google_info['email']
        
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = google_info
        mock_get.return_value = mock_response
        
        # Make the request to our endpoint
        response = self.client.post(self.url, {'access_token': 'fake_token'}, format='json')
        
        # Check that the response is an error
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

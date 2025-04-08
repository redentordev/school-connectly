from django.shortcuts import render, redirect
import requests
import urllib.parse
from django.conf import settings
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from allauth.socialaccount.models import SocialAccount
from singletons.logger_singleton import LoggerSingleton

logger = LoggerSingleton().get_logger()

# Create your views here.

def oauth_demo(request):
    """Render the Google OAuth demo page."""
    # Use the exact values from the Google credentials JSON
    auth_uri = "https://accounts.google.com/o/oauth2/auth"  # From the JSON
    client_id = "135591834469-2eh68nfpmuj5afhfqoi20fk816nmr04r.apps.googleusercontent.com"  # From the JSON
    
    # Get the current hostname for the redirect_uri
    host = request.get_host()
    protocol = 'https' if request.is_secure() else 'http'
    redirect_uri = f"{protocol}://{host}/api/auth/callback/"
    
    # Print for debugging
    print(f"Auth URI: {auth_uri}")
    print(f"Client ID: {client_id}")
    print(f"Redirect URI: {redirect_uri}")
    
    # Build params exactly as Google expects
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'token',
        'scope': 'openid email profile',
        'include_granted_scopes': 'true',
        'state': 'pass-through-value'
    }
    
    oauth_url = f"{auth_uri}?{urllib.parse.urlencode(params)}"
    
    context = {
        'oauth_url': oauth_url,
        'redirect_uri': redirect_uri
    }
    return render(request, 'authentication/demo.html', context)

def oauth_callback(request):
    """Handle the OAuth callback."""
    # The token will be in the URL fragment, which is not sent to the server
    # We'll redirect to the demo page with the token as a query parameter
    # The demo page will then extract the token and send it to our API
    return render(request, 'authentication/callback.html')

@api_view(['POST'])
@permission_classes([AllowAny])
def google_login(request):
    """
    Endpoint to handle Google OAuth login.
    
    Expects a token from the Google OAuth process.
    Returns a DRF token for authenticated API access.
    """
    # Validate input
    if 'access_token' not in request.data:
        return Response(
            {'error': 'Access token is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    token = request.data.get('access_token')
    
    try:
        # Verify the token with Google
        google_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if not google_response.ok:
            logger.error(f"Failed to verify Google token: {google_response.text}")
            return Response(
                {'error': 'Invalid Google token'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Parse user info from Google
        user_data = google_response.json()
        
        if 'email' not in user_data:
            logger.error("Email not provided in Google response")
            return Response(
                {'error': 'Email not provided by Google'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = user_data['email']
        google_id = user_data['sub']
        name = user_data.get('name', email.split('@')[0])
        picture = user_data.get('picture')
        
        # Handle user creation/authentication
        try:
            # Try to find if this Google account is already linked to a user
            social_account = SocialAccount.objects.filter(
                provider='google',
                uid=google_id
            ).first()
            
            if social_account:
                # If the account exists, get the user
                user = social_account.user
                logger.info(f"User {user.username} logged in via existing Google account")
            else:
                # Check if a user with this email already exists
                user = User.objects.filter(email=email).first()
                
                if user:
                    # Link the existing user to this Google account
                    SocialAccount.objects.create(
                        user=user,
                        provider='google',
                        uid=google_id,
                        extra_data=user_data
                    )
                    logger.info(f"Linked Google account to existing user {user.username}")
                else:
                    # Create a new user with the Google data
                    username = email.split('@')[0]
                    base_username = username
                    count = 1
                    
                    # Ensure username uniqueness
                    while User.objects.filter(username=username).exists():
                        username = f"{base_username}{count}"
                        count += 1
                    
                    # Create the new user
                    user = User.objects.create(
                        username=username,
                        email=email,
                        first_name=user_data.get('given_name', ''),
                        last_name=user_data.get('family_name', ''),
                        is_active=True
                    )
                    
                    # Set a unusable password for security
                    user.set_unusable_password()
                    user.save()
                    
                    # Create the social account
                    SocialAccount.objects.create(
                        user=user,
                        provider='google',
                        uid=google_id,
                        extra_data=user_data
                    )
                    logger.info(f"Created new user {user.username} from Google account")
            
            # Get or create token for the user
            token, created = Token.objects.get_or_create(user=user)
            
            # Update last login time
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Return the token to the client
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'picture': picture
            })
            
        except IntegrityError as e:
            logger.error(f"IntegrityError during Google login: {str(e)}")
            return Response(
                {'error': 'An account with this username already exists.'}, 
                status=status.HTTP_409_CONFLICT
            )
            
    except Exception as e:
        logger.error(f"Error during Google login: {str(e)}")
        return Response(
            {'error': 'An unexpected error occurred'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

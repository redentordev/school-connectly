from django.shortcuts import render, get_object_or_404
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Post, Comment
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.authentication import TokenAuthentication
from .permissions import IsPostAuthor, IsAdminOrReadOnly, IsAuthorOrReadOnly
from factories.post_factory import PostFactory
from singletons.config_manager import ConfigManager
from singletons.logger_singleton import LoggerSingleton
from rest_framework import viewsets
from rest_framework.decorators import action
from django.contrib.auth.models import User
from rest_framework.exceptions import PermissionDenied
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

logger = LoggerSingleton().get_logger()
config = ConfigManager()

# Create your views here.

def get_users(request):
    try:
        users = list(User.objects.values('id', 'username', 'email', 'created_at'))
        return JsonResponse(users, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = User.objects.create(username=data['username'], email=data['email'])
            return JsonResponse({'id': user.id, 'message': 'User created successfully'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)


def get_posts(request):
    try:
        posts = list(Post.objects.values('id', 'content', 'author', 'created_at'))
        return JsonResponse(posts, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def create_post(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            author = User.objects.get(id=data['author'])
            post = Post.objects.create(content=data['content'], author=author)
            return JsonResponse({'id': post.id, 'message': 'Post created successfully'}, status=201)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Author not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)


class UserListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            # Use create_user to properly hash the password
            user = User.objects.create_user(
                username=serializer.validated_data['username'],
                email=serializer.validated_data.get('email', ''),
                password=serializer.validated_data.get('password')
            )
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PostListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PostDetailView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            serializer = PostSerializer(post)
            return Response(serializer.data)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(request, post)
            serializer = PostSerializer(post, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(request, post)
            post.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)


class CommentListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing users.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="List all users",
        responses={200: UserSerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new user",
        request_body=UserSerializer,
        responses={201: UserSerializer()}
    )
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = User.objects.create_user(
                    username=serializer.validated_data['username'],
                    email=serializer.validated_data.get('email', ''),
                    password=serializer.validated_data.get('password')
                )
                logger.info(f"Successfully created user with ID: {user.id}")
                return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            if serializer.is_valid():
                user = serializer.save()
                logger.info(f"Successfully updated user with ID: {user.id}")
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            user_id = instance.id
            self.perform_destroy(instance)
            logger.info(f"Successfully deleted user with ID: {user_id}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PostViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing posts.
    """
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsAuthorOrReadOnly]

    @swagger_auto_schema(
        operation_description="List all posts",
        responses={200: PostSerializer(many=True)},
        manual_parameters=[
            openapi.Parameter(
                'page_size',
                openapi.IN_QUERY,
                description="Number of results to return per page",
                type=openapi.TYPE_INTEGER,
                default=10
            )
        ]
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new post",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['content', 'post_type'],
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'content': openapi.Schema(type=openapi.TYPE_STRING),
                'post_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=['text', 'image', 'video', 'link']
                ),
                'file_size': openapi.Schema(type=openapi.TYPE_INTEGER),
                'dimensions': openapi.Schema(type=openapi.TYPE_STRING),
                'duration': openapi.Schema(type=openapi.TYPE_INTEGER),
                'url': openapi.Schema(type=openapi.TYPE_STRING),
                'preview_image': openapi.Schema(type=openapi.TYPE_STRING),
            }
        ),
        responses={201: PostSerializer()}
    )
    def create(self, request, *args, **kwargs):
        # If metadata is already properly structured in the request, use it as is
        if isinstance(request.data.get('metadata'), dict):
            return super().create(request, *args, **kwargs)
            
        # Otherwise, extract metadata fields based on post type
        post_type = request.data.get('post_type')
        metadata = self._extract_metadata(request.data, post_type)
        
        # Update the request data with processed metadata
        data = request.data.copy()
        if metadata:
            data['metadata'] = metadata
        
        # Create a new request object with the modified data
        request._full_data = data
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            
            # Handle metadata updates based on post type
            post_type = request.data.get('post_type', instance.post_type)
            metadata = self._extract_metadata(request.data, post_type)
            
            # Update the request data with processed metadata
            data = request.data.copy()
            if metadata:
                data['metadata'] = metadata

            serializer = self.get_serializer(instance, data=data, partial=True)
            if serializer.is_valid():
                post = serializer.save()
                logger.info(f"Successfully updated post with ID: {post.id}")
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PermissionDenied:
            logger.error("Error updating post: You do not have permission to perform this action.")
            return Response(
                {'error': 'You do not have permission to perform this action.'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            logger.error(f"Error updating post: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            post_id = instance.id
            self.perform_destroy(instance)
            logger.info(f"Successfully deleted post with ID: {post_id}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except PermissionDenied:
            logger.error("Error deleting post: You do not have permission to perform this action.")
            return Response(
                {'error': 'You do not have permission to perform this action.'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            logger.error(f"Error deleting post: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def _extract_metadata(self, data, post_type):
        """Extract metadata based on post type."""
        metadata = {}
        if post_type == 'image':
            # Get metadata from either top-level or nested metadata
            metadata_source = data.get('metadata', {}) if isinstance(data.get('metadata'), dict) else {}
            file_size = data.get('file_size') or metadata_source.get('file_size')
            dimensions = data.get('dimensions') or metadata_source.get('dimensions')
            
            if file_size is not None:
                metadata['file_size'] = file_size
            if dimensions is not None:
                metadata['dimensions'] = dimensions
        elif post_type == 'video':
            metadata_source = data.get('metadata', {}) if isinstance(data.get('metadata'), dict) else {}
            file_size = data.get('file_size') or metadata_source.get('file_size')
            duration = data.get('duration') or metadata_source.get('duration')
            
            if file_size is not None:
                metadata['file_size'] = file_size
            if duration is not None:
                metadata['duration'] = duration
        elif post_type == 'link':
            metadata_source = data.get('metadata', {}) if isinstance(data.get('metadata'), dict) else {}
            url = data.get('url') or metadata_source.get('url')
            preview_image = data.get('preview_image') or metadata_source.get('preview_image')
            
            if url is not None:
                metadata['url'] = url
            if preview_image is not None:
                metadata['preview_image'] = preview_image
        return metadata

    @swagger_auto_schema(
        method='post',
        operation_description="Like a post",
        responses={
            200: openapi.Response(
                description="Post liked successfully",
                examples={
                    "application/json": {
                        "status": "post liked"
                    }
                }
            )
        }
    )
    @action(detail=True, methods=['post'])
    def like(self, request, pk=None):
        try:
            post = self.get_object()
            user = request.user
            logger.info(f"User {user.id} liked post {post.id}")
            return Response({'status': 'post liked'})
        except Exception as e:
            logger.error(f"Error liking post: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CommentViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing comments.
    """
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsAuthorOrReadOnly]

    @swagger_auto_schema(
        operation_description="List all comments",
        responses={200: CommentSerializer(many=True)}
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new comment",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['content', 'post'],
            properties={
                'content': openapi.Schema(type=openapi.TYPE_STRING),
                'post': openapi.Schema(type=openapi.TYPE_INTEGER),
            }
        ),
        responses={201: CommentSerializer()}
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            if serializer.is_valid():
                comment = serializer.save()
                logger.info(f"Updated comment {comment.id}")
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PermissionDenied:
            logger.error("Error updating comment: You do not have permission to perform this action.")
            return Response(
                {'error': 'You do not have permission to perform this action.'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            logger.error(f"Error updating comment: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            comment_id = instance.id
            self.perform_destroy(instance)
            logger.info(f"Deleted comment {comment_id}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except PermissionDenied:
            logger.error("Error deleting comment: You do not have permission to perform this action.")
            return Response(
                {'error': 'You do not have permission to perform this action.'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            logger.error(f"Error deleting comment: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserDetailView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAdminUser]

    def get_object(self, pk):
        return get_object_or_404(User, pk=pk)

    def get(self, request, pk):
        user = self.get_object(pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def put(self, request, pk):
        user = self.get_object(pk)
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        user = self.get_object(pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

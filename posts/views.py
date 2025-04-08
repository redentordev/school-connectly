from django.shortcuts import render, get_object_or_404
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Post, Comment, Like
from .serializers import UserSerializer, PostSerializer, CommentSerializer, LikeSerializer
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
from rest_framework.pagination import PageNumberPagination

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


class CommentPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


class NewsFeedPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


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
            ),
            201: openapi.Response(
                description="Post liked successfully",
                examples={
                    "application/json": {
                        "status": "post liked"
                    }
                }
            ),
            400: openapi.Response(description="Bad request"),
            409: openapi.Response(description="Already liked")
        }
    )
    @action(detail=True, methods=['post'])
    def like(self, request, pk=None):
        try:
            post = self.get_object()
            user = request.user
            
            # Check if user already liked this post
            if Like.objects.filter(user=user, post=post).exists():
                return Response({'status': 'already liked'}, status=status.HTTP_409_CONFLICT)
            
            # Create like
            like = Like.objects.create(user=user, post=post)
            logger.info(f"User {user.id} liked post {post.id}")
            return Response({'status': 'post liked'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error liking post: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='delete',
        operation_description="Unlike a post",
        responses={
            204: openapi.Response(description="Post unliked successfully"),
            404: openapi.Response(description="Like not found")
        }
    )
    @action(detail=True, methods=['delete'])
    def unlike(self, request, pk=None):
        try:
            post = self.get_object()
            user = request.user
            
            # Find and delete the like
            like = Like.objects.filter(user=user, post=post).first()
            if not like:
                return Response({'error': 'Like not found'}, status=status.HTTP_404_NOT_FOUND)
            
            like.delete()
            logger.info(f"User {user.id} unliked post {post.id}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error unliking post: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        operation_description="Get comments for a post",
        responses={
            200: CommentSerializer(many=True)
        },
        manual_parameters=[
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'page_size',
                openapi.IN_QUERY,
                description="Number of items per page",
                type=openapi.TYPE_INTEGER
            )
        ]
    )
    @action(detail=True, methods=['get'])
    def comments(self, request, pk=None):
        try:
            post = self.get_object()
            comments = Comment.objects.filter(post=post).order_by('-created_at')
            
            # Paginate results
            paginator = CommentPagination()
            paginated_comments = paginator.paginate_queryset(comments, request)
            serializer = CommentSerializer(paginated_comments, many=True)
            
            return paginator.get_paginated_response(serializer.data)
        except Exception as e:
            logger.error(f"Error retrieving comments: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='post',
        operation_description="Add a comment to a post",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['text'],
            properties={
                'text': openapi.Schema(type=openapi.TYPE_STRING),
            }
        ),
        responses={
            201: CommentSerializer()
        }
    )
    @action(detail=True, methods=['post'])
    def comment(self, request, pk=None):
        try:
            post = self.get_object()
            serializer = CommentSerializer(data={'text': request.data.get('text'), 'post': post.id}, context={'request': request})
            
            if serializer.is_valid():
                serializer.save(author=request.user, post=post)
                logger.info(f"User {request.user.id} commented on post {post.id}")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error adding comment: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        operation_description="Get personalized news feed",
        responses={
            200: PostSerializer(many=True)
        },
        manual_parameters=[
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'page_size',
                openapi.IN_QUERY,
                description="Number of items per page",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'filter',
                openapi.IN_QUERY,
                description="Filter type (all, liked, own, followed)",
                type=openapi.TYPE_STRING,
                default='all'
            ),
            openapi.Parameter(
                'post_type',
                openapi.IN_QUERY,
                description="Filter by post type (text, image, video, link)",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'metadata_key',
                openapi.IN_QUERY,
                description="Filter by specific metadata key (e.g., 'file_size', 'dimensions', 'duration', 'url')",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'metadata_value',
                openapi.IN_QUERY,
                description="Filter by metadata value (used with metadata_key)",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'metadata_min',
                openapi.IN_QUERY,
                description="Filter by minimum metadata value (used with metadata_key for range filtering)",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'metadata_max',
                openapi.IN_QUERY,
                description="Filter by maximum metadata value (used with metadata_key for range filtering)",
                type=openapi.TYPE_STRING
            )
        ]
    )
    @action(detail=False, methods=['get'])
    def feed(self, request):
        """
        Get a personalized news feed with advanced filtering options.
        
        This endpoint supports:
        1. Basic filtering: all, liked, own posts
        2. Post type filtering: text, image, video, link
        3. Metadata filtering:
            - Exact match: Use metadata_key and metadata_value
            - Range filtering: Use metadata_key with metadata_min and/or metadata_max
        
        Examples:
        - Get posts with file_size=1024: ?metadata_key=file_size&metadata_value=1024
        - Get posts with file_size >= 1000: ?metadata_key=file_size&metadata_min=1000
        - Get posts with duration <= 120: ?metadata_key=duration&metadata_max=120
        - Get posts with 100 <= file_size <= 5000: ?metadata_key=file_size&metadata_min=100&metadata_max=5000
        """
        try:
            user = request.user
            filter_type = request.query_params.get('filter', 'all')
            post_type = request.query_params.get('post_type', None)
            metadata_key = request.query_params.get('metadata_key', None)
            metadata_value = request.query_params.get('metadata_value', None)
            metadata_min = request.query_params.get('metadata_min', None)
            metadata_max = request.query_params.get('metadata_max', None)
            
            # Base queryset - ordered by created_at in descending order (newest first)
            queryset = Post.objects.select_related('author').prefetch_related('likes', 'comments').order_by('-created_at')
            
            # Apply filtering based on request parameters
            if filter_type == 'liked':
                # Posts liked by the current user
                queryset = queryset.filter(likes__user=user)
            elif filter_type == 'own':
                # Posts created by the current user
                queryset = queryset.filter(author=user)
            # Note: 'followed' filter would be implemented if there was a 'Follow' model
            # elif filter_type == 'followed':
            #     # Posts from users that the current user follows
            #     followed_users = user.following.values_list('followed_user_id', flat=True)
            #     queryset = queryset.filter(author_id__in=followed_users)
            
            # Filter by post type if specified
            if post_type:
                queryset = queryset.filter(post_type=post_type)
            
            # Filter by metadata if key and value are provided
            if metadata_key:
                if metadata_value:
                    # We need a different approach - the metadata is stored as JSON text in the database
                    # Let's use a simple LIKE query to search for the value in the JSON text
                    search_string = f'"{metadata_key}": {metadata_value}'
                    # If the value is a string, we need to add quotes
                    if not metadata_value.isdigit():
                        search_string = f'"{metadata_key}": "{metadata_value}"'
                    
                    # Get all posts with this key first
                    key_posts = queryset.filter(_metadata__contains=f'"{metadata_key}":')
                    
                    # Then filter them manually to ensure exact match
                    filtered_ids = []
                    for post in key_posts:
                        metadata_dict = post.metadata
                        if metadata_dict and metadata_key in metadata_dict:
                            # For numeric values, compare as numbers
                            if metadata_value.isdigit():
                                if str(metadata_dict[metadata_key]) == metadata_value:
                                    filtered_ids.append(post.id)
                            # For string values, compare as strings
                            else:
                                if metadata_dict[metadata_key] == metadata_value:
                                    filtered_ids.append(post.id)
                    
                    queryset = queryset.filter(id__in=filtered_ids)
                elif metadata_min or metadata_max:
                    # For range filtering, we'll need to first get all posts with the metadata key
                    key_posts = queryset.filter(_metadata__contains=f'"{metadata_key}":')
                    
                    if metadata_min:
                        try:
                            # Convert to numeric value
                            min_value = float(metadata_min)
                            # Then filter posts manually
                            filtered_ids = []
                            for post in key_posts:
                                try:
                                    if post.metadata.get(metadata_key, 0) >= min_value:
                                        filtered_ids.append(post.id)
                                except (ValueError, TypeError):
                                    pass
                            queryset = queryset.filter(id__in=filtered_ids)
                        except ValueError:
                            # If conversion fails, return empty queryset
                            queryset = queryset.none()
                    
                    if metadata_max:
                        try:
                            # Convert to numeric value
                            max_value = float(metadata_max)
                            # Then filter posts manually
                            filtered_ids = []
                            for post in key_posts:
                                try:
                                    if post.metadata.get(metadata_key, float('inf')) <= max_value:
                                        filtered_ids.append(post.id)
                                except (ValueError, TypeError):
                                    pass
                            queryset = queryset.filter(id__in=filtered_ids)
                        except ValueError:
                            # If conversion fails, return empty queryset
                            queryset = queryset.none()
            
            # Paginate results
            paginator = NewsFeedPagination()
            paginated_posts = paginator.paginate_queryset(queryset, request)
            serializer = self.get_serializer(paginated_posts, many=True)
            
            logger.info(f"User {user.id} retrieved news feed with filter: {filter_type}")
            return paginator.get_paginated_response(serializer.data)
        
        except Exception as e:
            logger.error(f"Error retrieving news feed: {str(e)}")
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

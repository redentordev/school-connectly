"""
URL configuration for connectly project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.views import obtain_auth_token

# Construct the server URL
PROTOCOL = "https" if settings.CSRF_COOKIE_SECURE else "http"
SERVER_URL = f"{PROTOCOL}://{settings.ALLOWED_HOSTS[0]}" if settings.ALLOWED_HOSTS else "http://localhost:8000"

schema_view = get_schema_view(
    openapi.Info(
        title="Connectly API",
        default_version='v1',
        description="API documentation for Connectly social media platform",
        terms_of_service="https://www.connectly.com/terms/",
        contact=openapi.Contact(email="contact@connectly.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    url=SERVER_URL,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Auth endpoints
    path('api/auth/token/', csrf_exempt(obtain_auth_token), name='api-token-auth'),
    
    # API endpoints
    path('api/', include('posts.urls')),
    
    # Swagger documentation - both at root and /swagger/ for convenience
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui-alt'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # OpenAPI schema
    path('swagger.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),
]

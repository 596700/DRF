from django.urls import path
from django.conf.urls import include
from rest_framework import routers
from apiv1.views import ( 
    UserViewSet, ProductViewSet, VersionViewSet,
    ProductVersionViewSet, VulnerabilityViewSet,
    CommentViewSet, UserAPIView, UserActivationAPIView,
    UserAPIView, UserRetrieveView
)

router = routers.DefaultRouter()
router.register('users', UserViewSet)
router.register('products', ProductViewSet)
router.register('versions', VersionViewSet)
router.register('productver', ProductVersionViewSet)
router.register('vulnerabilities', VulnerabilityViewSet)
router.register('comments', CommentViewSet)

app_name = 'apiv1'
urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls')),
    path('user/', UserAPIView.as_view()),
    path('user/create/complete/<token>/', UserActivationAPIView.as_view(), name='user_create_complete'),
    path('user/<pk>/', UserRetrieveView.as_view()),
]
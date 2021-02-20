from django.shortcuts import render
from rest_framework import viewsets, status, views
from django.contrib.auth import get_user_model
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticatedOrReadOnly

# Userアクティベーション用
from rest_framework.response import Response
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.core.signing import BadSignature, SignatureExpired, loads, dumps
from django.http import Http404, HttpResponseBadRequest
from django.template.loader import render_to_string
from django.core.mail import send_mail

from .serializers import ( 
    UserSerializer, ProductSerializer, VersionSerializer,
    ProductVersionSerializer, VulnerabilitySerializer,
    CommentSerializer
)
from .models import (
    Product, Version, ProductVersion,
    Vulnerability, Comment
)

from users.permissions import IsOwnerOrReadOnly, IsCreatorOrReadOnly


# Create your views here.

User = get_user_model()

# APIView
class UserAPIView(views.APIView):

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        current_site = get_current_site(self.request)
        domain = current_site.domain
        context = {
            'protocol': self.request.scheme,
            'domain': domain,
            'token': dumps(serializer.data['id']),
            'user': serializer.data['username'],
        }

        subject = render_to_string('apiv1/subject.txt', context)
        message = render_to_string('apiv1/message.txt', context)
        from_email = '596700@gmail.com'
        to_email = serializer.data['email']
        send_mail(subject, message, from_email, [to_email])

        return Response(serializer.data, status.HTTP_201_CREATED)

    def get(self, request, format=None):
        usernames = [user.username for user in User.objects.all()]
        return Response(usernames)

class UserActivationViewSet(views.APIView):

    timeout_seconds = getattr(settings, 'ACTIVATION_TIMEOUT_SECONDS', 60*60*24)
    
    def get(self, request, *args, **kwargs):

        token = kwargs.get('token')
        try:
            user_id = loads(token, max_age=self.timeout_seconds)
        # If token has Expired
        except SignatureExpired:
            return Response(status.HTTP_400_BAD_REQUEST)
        # Bad token
        except BadSignature:
            return Response(status.HTTP_400_BAD_REQUEST)
        # Success
        else:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(status.HTTP_404_NOT_FOUND)
            else:
                if not user.is_active:
                    user.is_active = True
                    user.save()
                    return Response(status.HTTP_200_OK)
        return Response(status.HTTP_400_BAD_REQUEST)



class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsOwnerOrReadOnly]

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]

class VersionViewSet(viewsets.ModelViewSet):
    queryset = Version.objects.all()
    serializer_class = VersionSerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]

class ProductVersionViewSet(viewsets.ModelViewSet):
    queryset = ProductVersion.objects.all()
    serializer_class = ProductVersionSerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]

class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(creator=self.request.user, updater=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updater=self.request.user)

class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(creator=self.request.user)
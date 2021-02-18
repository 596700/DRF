from django.shortcuts import render
from rest_framework import viewsets
from django.contrib.auth import get_user_model
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticatedOrReadOnly

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
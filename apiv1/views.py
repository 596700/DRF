from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, status, views
from django.contrib.auth import get_user_model
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.pagination import PageNumberPagination

# Filtering
from django_filters import rest_framework as filters
from django.db.models import Q

# Userアクティベーション用
from rest_framework.response import Response
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.core.signing import (
    BadSignature, SignatureExpired, loads, dumps
)
from django.template.loader import render_to_string
from django.core.mail import send_mail

# トランザクション
from django.db import transaction

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

# Pagenation
class BasicPagination(PageNumberPagination):
    page_size_query_param = 'limits'

# APIView
class UserAPIView(views.APIView):

    permission_classes = [IsOwnerOrReadOnly]

    # Pagenation
    pagination_class = BasicPagination

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

    def get(self, request, *args, **kwargs):
        # 本登録済みのユーザーのみを表示
        if request.query_params:
            username = request.query_params.get('username')
            queryset = User.objects.filter(Q(username__icontains=username), is_active=True).order_by('-id')
        else:
            queryset = User.objects.filter(is_active=True).order_by('-id')    
        paginator = BasicPagination()
        result = paginator.paginate_queryset(queryset, request)
        serializer = UserSerializer(instance=result, many=True)
        return Response(serializer.data, status.HTTP_200_OK)


class UserRetrieveView(views.APIView):

    permission_classes = [IsOwnerOrReadOnly]
    
    def get(self, request, pk, *args, **kwargs):
        # モデルを取得
        user = get_object_or_404(User, pk=pk)
        # シリアライザを作成
        serializer = UserSerializer(instance=user)
        return Response(serializer.data, status.HTTP_200_OK)

    # 更新・一部更新
    def put(self, request, pk, *args, **kwargs):
        # モデルを取得
        user = get_object_or_404(User, pk=pk)
        # シリアライザを作成
        serializer = UserSerializer(instance=user, data=request.data)
        # バリデーションを実行
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status.HTTP_200_OK)

    # 一部更新
    def patch(self, request, pk, *args, **kwargs):
        # モデルを取得
        user = get_object_or_404(User, pk=pk)
        # シリアライザを作成
        serializer = UserSerializer(instance=user, data=request.data, partical=True)
        # バリデーションを実行
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status.HTTP_200_OK)

    def delete(self, request, pk, *args, **kwargs):
        # モデルを取得
        user = get_object_or_404(User, pk=pk)
        # モデルを削除
        user.delete()
        return Response(status.HTTP_204_NO_CONTENT)

class UserActivationAPIView(views.APIView):

    timeout_seconds = getattr(settings, 'ACTIVATION_TIMEOUT_SECONDS', 60*60*24)
    
    def get(self, request, *args, **kwargs):

        token = kwargs.get('token')
        # Token decode
        try:
            user_id = loads(token, max_age=self.timeout_seconds)
        # Token has Expired
        except SignatureExpired:
            return Response(status.HTTP_400_BAD_REQUEST)
        # Bad token
        except BadSignature:
            return Response(status.HTTP_400_BAD_REQUEST)
        # Token decode後の処理
        else:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(status.HTTP_404_NOT_FOUND)
            else:
                # user.is_active=Trueにして正常終了
                if not user.is_active:
                    user.is_active = True
                    user.save()
                    return Response(status.HTTP_200_OK)
        return Response(status.HTTP_400_BAD_REQUEST)


# 開発終了後削除し、APIViewに移行する
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsOwnerOrReadOnly]

class ProductFilter(filters.FilterSet):
    name = filters.CharFilter(lookup_expr='icontains')
    vendor = filters.CharFilter(lookup_expr='icontains')
    part = filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = Product
        fields = ['name', 'vendor', 'part']

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]
    filter_class = ProductFilter

    @transaction.atomic
    def perform_create(self, serializer):
        serializer.save()

class VersionFilter(filters.FilterSet):
    version = filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = Version
        fields = ['version']

class VersionViewSet(viewsets.ModelViewSet):
    queryset = Version.objects.all()
    serializer_class = VersionSerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]
    filter_class = VersionFilter

class ProductVersionFilter(filters.FilterSet):
    name = filters.CharFilter(field_name='name__name', lookup_expr='icontains')
    version = filters.CharFilter(field_name='version__version', lookup_expr='icontains')

class ProductVersionViewSet(viewsets.ModelViewSet):
    queryset = ProductVersion.objects.all()
    serializer_class = ProductVersionSerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]
    filter_class = ProductVersionFilter

class VulnerabilityFilter(filters.FilterSet):
    """
    資産に結びついている脆弱性に対処することを主な利用と考えているため、
    ひとまず検索についてはCVEと影響下の製品のみ対処する
    """
    cve_id = filters.CharFilter(lookup_expr='icontains')
    # リレーション先が更に中間テーブルであるため、冗長なquerysetとなっている
    affected_software = filters.CharFilter(field_name='affected_software__name__name', lookup_expr='icontains')
    
    class Meta:
        model = Vulnerability
        fields = ['cve_id', 'affected_software']

class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticatedOrReadOnly&IsCreatorOrReadOnly]
    filter_class = VulnerabilityFilter

    @transaction.atomic
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
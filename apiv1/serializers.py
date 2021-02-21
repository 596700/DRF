from rest_framework import serializers
from rest_framework.fields import CurrentUserDefault, CreateOnlyDefault
from django.contrib.auth import get_user_model
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone

# User Activate
from django.core.signing import BadSignature, SignatureExpired, loads, dumps
from django.contrib.auth.tokens import default_token_generator

from .models import ( 
    Product, Version, ProductVersion, Vulnerability, Comment
)

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    # 仮登録状態にするためにis_active=Falseにする
    is_active = serializers.HiddenField(default=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'watch_list', 'is_active']
        extra_kwargs = {'password': {'write_only': True, 'required': True}}
        

    def create(self, validated_data):
        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']
        is_active = validated_data['is_active']
        user = User(username=username, email=email, password=make_password(password), is_active=is_active)
        user.save()
        return user


class ProductSerializer(serializers.ModelSerializer):
    
    creator = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentUserDefault()))

    class Meta:
        # 対象のモデル
        model = Product
        # 利用するフィールド
        fields = ['id', 'name', 'part', 'vendor', 'url', 'creator']

class VersionSerializer(serializers.ModelSerializer):

    creator = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentUserDefault()))

    class Meta:
        model = Version
        fields = ['id', 'version', 'name', 'creator']

class ProductVersionSerializer(serializers.ModelSerializer):
    
    creator = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentUserDefault()))

    class Meta:
        model = ProductVersion
        # 逆参照のrelated_name=vulnerabilityをfieldsに入れる
        fields = ['id', 'name', 'version', 'creator', 'created_at', 'vulnerability']


class VulnerabilitySerializer(serializers.ModelSerializer):

    class Meta:
        model = Vulnerability
        exclude = ['ver']
        depth = 1
    
    # creator, updaterはviewsでperform_method(create, update)処理している
    creator = serializers.PrimaryKeyRelatedField(read_only=True)
    updater = serializers.PrimaryKeyRelatedField(read_only=True)
    affected_software = serializers.PrimaryKeyRelatedField(many=True, queryset=ProductVersion.objects.all())

class CommentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Comment
        # fields = '__all__'
        fields = ['id', 'vulnerability', 'comment', 'creator', 'created_at']
        depth = 1
    
    vulnerability = serializers.PrimaryKeyRelatedField(queryset=Vulnerability.objects.all())
    creator = serializers.PrimaryKeyRelatedField(default=serializers.CreateOnlyDefault(CurrentUserDefault()), read_only=True)
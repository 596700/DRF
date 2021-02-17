from rest_framework import serializers
from rest_framework.fields import CurrentUserDefault, CreateOnlyDefault
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone

# from drf_writable_nested import WritableNestedModelSerializer

from .models import ( 
    Product, Version, ProductVersion, Vulnerability, Comment
)

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True, 'required': True}}
        

    def create(self, validated_data):
        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']
        user = User(username=username, email=email, password=make_password(password))
        user.save()
        return user


class ProductSerializer(serializers.ModelSerializer):
    
    creator = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentUserDefault()))

    class Meta:
        # 対象のモデル
        model = Product
        # 利用するフィールド
        fields = '__all__'

class VersionSerializer(serializers.ModelSerializer):

    creator = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentUserDefault()))

    class Meta:
        model = Version
        fields = '__all__'

class ProductVersionSerializer(serializers.ModelSerializer):
    
    creator = serializers.HiddenField(default=serializers.CreateOnlyDefault(CurrentUserDefault()))

    class Meta:
        model = ProductVersion
        # 逆参照のrelated_name=vulnerabilityをfieldsに入れる
        fields = ['id', 'name', 'version', 'creator', 'created_at', 'vulnerability']


class VulnerabilitySerializer(serializers.ModelSerializer):

    class Meta:
        model = Vulnerability
        fields = '__all__'
        depth = 1
    
    creator = serializers.PrimaryKeyRelatedField(default=serializers.CreateOnlyDefault(CurrentUserDefault()), read_only=True)
    updater = serializers.PrimaryKeyRelatedField(default=CurrentUserDefault(), read_only=True)
    # modelsの方でauto_now_add=Trueにしているため不要？
    # created_at = serializers.DateTimeField(default=serializers.CreateOnlyDefault(timezone.now))
    # updated_at = serializers.HiddenField(default=timezone.now)
    affected_software = serializers.PrimaryKeyRelatedField(many=True, queryset=ProductVersion.objects.all())

class CommentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Comment
        fields = '__all__'
        depth = 1
    
    creator = serializers.PrimaryKeyRelatedField(default=serializers.CreateOnlyDefault(CurrentUserDefault()), read_only=True)
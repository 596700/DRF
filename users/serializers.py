# from django.contrib.auth import authenticate, get_user_model
# from djoser.conf import settings
# from djoser.serializers import TokenCreateSerializer

# User = get_user_model()

# # djoser version == 2.1.0
# class CustomTokenCreateSerializer(TokenCreateSerializer):


#     def validate(self, attrs):
#         password = attrs.get("password")
#         params = {settings.LOGIN_FIELD: attrs.get(settings.LOGIN_FIELD)}
#         self.user = authenticate(
#             request=self.context.get("request"), **params, password=password
#         )
#         if not self.user:
#             self.user = User.objects.filter(**params).first()
#             if self.user and not self.user.check_password(password):
#                 self.fail("invalid_credentials")
#         # and self.user.is_active
#         if self.user:
#             return attrs
#         self.fail("invalid_credentials")
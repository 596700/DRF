from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
import requests

# Create your views here.

# class UserActivationView(APIView):
#     def get(self, reqeust, uid, token):
#         protocol = 'https://' if request.is_secre() else 'http://'
#         web_url = protocol + request.get_host()
#         post_url = web_url + "/activate/"
#         post_data = {'uid': uid, 'token': token}
#         result = requests.post(post_url, data=post_data)
#         content = result.text()
#         return Response(content)
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from accounts.serializers import UserSerializer
from django.contrib.auth.models import User

class UserCreate(APIView):
    """
    Creates the user.
    """

    def post(self, request, format='json'):
        return Response('hello')

def logout_user(request):
    return render(request, 'accounts/logout.html', {})

def login_form(request):
    return render(request, 'accounts/login.html', {})

def get_auth_token(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    user = authenticate(username=username, password=password)
    if user is not None:
        # the password verified for the user
        if user.is_active:
            token, created = Token.objects.get_or_create(user=user)
            request.session['auth'] = token.key
            return redirect('/polls/', request)
    return redirect(settings.LOGIN_URL, request)

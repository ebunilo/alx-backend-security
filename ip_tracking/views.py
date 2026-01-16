from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from ratelimit.decorators import ratelimit
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods


def get_rate_limit(request):
    """
    Determine rate limit based on authentication status.
    - 10 requests/minute for authenticated users
    - 5 requests/minute for anonymous users
    """
    if request.user.is_authenticated:
        return '10/m'
    return '5/m'


@ratelimit(key='ip', rate=get_rate_limit, method='POST')
@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view with rate limiting:
    - 10 requests/minute for authenticated users
    - 5 requests/minute for anonymous users
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    
    return render(request, 'login.html')


@login_required
@ratelimit(key='ip', rate='10/m', method='GET')
def sensitive_data(request):
    """Protected endpoint for authenticated users only with rate limiting"""
    return HttpResponse("Sensitive data here")


def home(request):
    """Home page"""
    return HttpResponse("Welcome to IP Tracking System")

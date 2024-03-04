from django.shortcuts import render
import logging
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
# Create your views here.
from django.views.decorators.csrf import csrf_protect
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserRegisterForm
from .models import CustomUser

logger = logging.getLogger(__name__)
import asyncio



def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")




def user_login(request):
    if request.method == "POST":
        name = request.POST.get('name')
        password = request.POST.get('password')

        try:
            user = CustomUser.objects.get(username=name, password=password)
            request.session['userid'] = user.id
            return HttpResponse("Hello, world. You're at login index.")
        except CustomUser.DoesNotExist:
            pass

        user = authenticate(request, username=name, password=password)
        if user is not None and user.is_active:
            login(request, user)
            return  HttpResponse("Hello, world. You're at next index.")
        else:
            messages.error(request, 'Username or password does not match')
            return redirect('user_login')

    return render(request, 'users/user_login.html')

@csrf_protect
def user_register(request):
    
    if request.method == "POST":
        
        form = UserRegisterForm(request.POST)
        print(form.is_valid())  # Check if the form is considered valid
        if form.is_valid():
            print(form.cleaned_data)  # Check the cleaned data before saving
            form.save()
            messages.success(request, 'You have been successfully registered!')
            return redirect('user_login')
        else:
            print(form.errors)  # Print form errors for further investigation
    else:
        form = UserRegisterForm()

    return render(request, 'users/user_register.html', {'form': form})


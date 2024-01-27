from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.



from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserRegisterForm
def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")

def user_register(request):
    if request.method == "POST":
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'You have been successfully registered!')
            return redirect('user_login')
    else:
        form = UserRegisterForm()

    return render(request, 'users/user_register.html', {'form': form})

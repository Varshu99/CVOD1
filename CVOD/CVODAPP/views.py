from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout as auth_logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib import messages
import re

# Base view
def base(request):
    return render(request, 'CVODAPP/base.html')
# Home page
def index(request):
    return render(request, 'CVODAPP/index.html')

def signin(request):
    if request.user.is_authenticated:
        messages.info(request, "You are already logged in.")
        return redirect("main")  # change index → main

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            messages.success(request, f"Welcome back, {user.username}!")
            return redirect("main")  # change index → main
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "CVODAPP/signin.html")

# Signup view
def signup(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validations
        if not all([username, email, password, confirm_password]):
            messages.error(request, "Please fill all fields.")
        elif password != confirm_password:
            messages.error(request, "Passwords do not match.")
        elif len(password) < 6:
            messages.error(request, "Password must be at least 6 characters.")
        elif username[0].isdigit():
            messages.error(request, "Username should not start with a digit.")
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messages.error(request, "Enter a valid email address.")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
        elif User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
        elif not re.search(r'[A-Z]', password):
            messages.error(request, "Password must contain an uppercase letter.")
        elif not re.search(r'[a-z]', password):
            messages.error(request, "Password must contain a lowercase letter.")
        elif not re.search(r'\d', password):
            messages.error(request, "Password must contain a digit.")
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            messages.error(request, "Password must contain a special character.")
        else:
            # Create user
            User.objects.create_user(username=username, email=email, password=password)
            messages.success(request, "Account created successfully! Please login.")
            return redirect('signin')

    return render(request, 'CVODAPP/signup.html')

# Logout
def logout(request):
    auth_logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('signin')



# Forgot password (step 1: enter username)
def forgot(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            user = User.objects.get(username=username)
            return redirect('resetpass', username=username)
        except User.DoesNotExist:
            messages.error(request, "Username does not exist.")
    return render(request, 'CVODAPP/forgot.html')


def main(request):
    return render(request, 'CVODAPP/main.html')


# Password reset view
def resetpass(request, username):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not new_password or not confirm_password:
            messages.error(request, "Both password fields are required.")
            return redirect('resetpass', username=username)

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('resetpass', username=username)

        try:
            user = User.objects.get(username=username)
            user.password = make_password(new_password)
            user.save()
            messages.success(request, "Password reset successfully. Please sign in.")
            return redirect('signin')
        except User.DoesNotExist:
            messages.error(request, "User not found.")
            return redirect('forgot')

    return render(request, 'resetpass.html', {'username': username})


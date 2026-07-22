from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required

def home(request):
    return render(request, "landing/home.html")

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages


def home(request):
    return render(request, "landing/home.html")


def user_login(request):

    # Only accept POST requests
    if request.method != "POST":
        return redirect("home")

    username = request.POST.get("username", "").strip()
    password = request.POST.get("password", "")

    user = authenticate(
        request,
        username=username,
        password=password,
    )

    if user is not None:

        login(request, user)

        messages.success(
            request,
            f"Welcome back, {user.username}!"
        )

        return redirect("dashboard")

    # Login failed
    messages.error(
        request,
        "Incorrect username or password."
    )

    return render(
        request,
        "landing/home.html",
        {
            "show_login_modal": True,
            "username": username,
        },
    )


def logout_view(request):

    logout(request)

    messages.success(
        request,
        "You have been logged out successfully."
    )

    return redirect("home")



def logout_view(request):
    logout(request)
    return redirect("home")


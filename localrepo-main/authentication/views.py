from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages,auth
from django.core.mail import EmailMessage, send_mail
from hello import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate, login, logout
from . tokens import generate_token
from django.contrib.auth.forms import AuthenticationForm

# Create your views here.
def home(request):
    return render(request, "authentication/index.html")

def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['password']
        pass2 = request.POST['confirm_password']
        
        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('home')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email Already Registered!!")
            return redirect('home')
        
        if len(username)>20:
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('home')
        
        if pass1 != pass2:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('home')
        
        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('home')
        
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
    
        myuser.is_active = False
        myuser.save()
        messages.success(request, "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
        
        # Welcome Email
        subject = "Welcome to our- Django Login!!"
        message = "Hello " + myuser.first_name + "!! \n" + "Welcome to our website!! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\nAkhilesh Kumar Mishra"        
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        
        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ - Django Login!!"
        message2 = render_to_string('email_confirmation.html',{
            
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER,
        [myuser.email],
        )
        email.fail_silently = True
        email.send()
        
        return redirect('signin')
        
        
    return render(request, "authentication/signup.html")


def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html',{"fname":"Guest"})


def signin(request):
    if request.method == 'POST':
        # Retrieve username and password from the POST data
        username = request.POST['username']
        password = request.POST['password']
        print(username,password)
         # Use authenticate to check the credentials
        user = authenticate(username=username, password=password)
        print(username,password)
        print("user=",user)

        if user is not None:
             # If user is authenticated, log them in
            login(request, user)
            # Redirect to the home page or any other desired page
            messages.success(request, "Logged In Sucessfully!!")
            return render(request, "authentication/index.html",{"fname":user.first_name})
        else:
            # If authentication fails, display an error message
            messages.error(request, "Bad Credentials!!")
            return redirect('home')
    
    return render(request, "authentication/signin.html")

'''def signin(request):
    if request.method == 'POST':
        # Use Django's built-in AuthenticationForm to handle user authentication
        form = AuthenticationForm(request, request.POST)

        # Print the values of username and password
        print("Username:",form['username'].value())
        print("Password:",form['password'].value())

        # Check if the form is valid
        if form.is_valid():
            # Authenticate the user using the provided credentials
            user = form.get_user()

            # Log in the user
            login(request, user)

            # Print the values of username and password
            print("Username:", form.cleaned_data['username'])
            print("Password:", form.cleaned_data['password'])

            # Redirect to the home page or any other desired page
            print("inside if\n")
        
            return render(request, "authentication/index.html", {"fname": user.first_name})
        else:
             # Print form errors
            print("Form Errors:", form.errors)

            # If the form is not valid, display an error message
            print("inside else\n")
            messages.error(request, "Invalid username or password.")
            return redirect('home')

    return render(request, "authentication/signin.html")'''


def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!!")
    return redirect('home')
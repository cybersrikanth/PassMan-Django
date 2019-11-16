import base64
import random
import secrets
from .models import PassWords
from Crypto import Random
from django.contrib import auth, messages
from django.shortcuts import render, redirect
from django.contrib.auth.models import User, auth
from django.contrib.auth import get_user_model
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

user = get_user_model()
capsAlpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
smallAlpha = 'abcdefghijklmnopqrstuvwxyz'
numbers = '0123456789'
specialChar = '!@#()*.<>?/&^%+'

pass1 = None


def register(request):
    if request.method == 'POST':
        first = request.POST['first']
        last = request.POST['last']
        username = request.POST['username']
        pass1 = request.POST['password1']
        pass2 = request.POST['password2']
        email = request.POST['email']
        if User.objects.filter(username=username).exists():
            messages.info(request, 'Username taken')
            return redirect('register')
        elif User.objects.filter(email=email).exists():
            messages.info(request, 'Email already exists, try login')
            return redirect('register')
        else:
            user = User.objects.create_user(username=username, password=pass1, email=email, first_name=first,
                                            last_name=last)
            user.save()

            return redirect('login')
    else:
        return render(request, 'registration.html')


def login(request):
    global pass1
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)
            pass1 = password
            return redirect('home')
        else:
            messages.error(request, 'invalid credentials')
            return redirect('login')
    else:
        return render(request, 'login.html')


def logout(request):
    auth.logout(request)
    return redirect('login')


def home(request):
    if request.method == 'POST':
        url = request.POST['url']
        username = request.POST['username']
        length = request.POST['password']
        passwd = generatePass(int(length))
        try:
            update = request.POST['update']
        except KeyError:
            update = False
        if PassWords.objects.filter(username=username, website=url).exists() and not update:
            messages.info(request, 'data already exists')
            messages.info(request, 'If you like to update password please check the above checkbox')
            return render(request, 'MyPass.html')
        elif not PassWords.objects.filter(username=username, website=url).exists():
            tmp = PassWords(username=username,
                            passwd=encrypt(passwd, pass1).decode(),
                            website=url,
                            user_id=request.user.id)
            tmp.save()
            messages.info(request, 'data inserted successfully')
            messages.info(request, 'Generated password: ' + passwd)
            return render(request, 'MyPass.html')
        else:
            PassWords.objects.filter(username=username,
                                     website=url).update(passwd=encrypt(passwd, pass1).decode())
            messages.info(request, 'password updated')
            messages.info(request, 'new password: ' + passwd)
            return render(request, 'MyPass.html')
    else:
        return render(request, 'MyPass.html')


def generatePass(length):
    mix = (capsAlpha, smallAlpha, numbers, specialChar)
    passwd = [secrets.choice(mix[i]) if i < len(mix) else secrets.choice(mix[random.randint(0, 3)]) for i in
              range(length)]
    random.shuffle(passwd)
    return ''.join(passwd)


def passwd(request):
    global pass1
    if request.method == 'POST':
        password = request.POST['password']
        if auth.authenticate(username=request.user, password=password):
            pass1 = password
            passwords = PassWords.objects.filter(user_id=request.user)
            d = {'data': conv_to_list(passwords)}
            return render(request, 'pass.html', d)
        else:
            messages.error(request, "Invalid password")
            return render(request, 'pass.html')
    else:
        return render(request, 'pass.html')


def conv_to_list(obj):
    l = []
    for i in obj:
        d = {
            'url': i.website,
            'user': i.username,
            'pass': decrypt(i.passwd, pass1).decode()
        }
        l.append(d)
    return l


BLOCK_SIZE = 16


def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def get_private_key(password):
    salt = '123edghy8ik'.encode()
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key


def encrypt(raw, password):
    private_key = get_private_key(password)
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc, password):
    private_key = get_private_key(password)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

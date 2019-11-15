from django.db import models
from django.contrib.auth import get_user_model

user = get_user_model()


# Create your models here.
class PassWords(models.Model):
    website = models.TextField()
    user = models.ForeignKey(user, on_delete=models.CASCADE)
    username = models.TextField()
    passwd = models.TextField()


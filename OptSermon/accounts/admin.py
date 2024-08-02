from django.contrib import admin

# Register your models here.
from .models import UserCustom, OneTimePassword

admin.site.register(UserCustom)
admin.site.register(OneTimePassword)

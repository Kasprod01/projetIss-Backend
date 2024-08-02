from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email


class UserCustomManager(BaseUserManager):
    def valider_son_email(self,email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_("Please enter a valid email address"))

    #objects.create_user
    def create_user(self,email,first_name,last_name,password,**extra_fields):
        if email:
            email = self.normalize_email(email)
            self.valider_son_email(email)
        else:
            raise ValueError(_('An email adresse is required'))
        if not first_name:
            raise ValueError(_('A  first_name is required'))
        if not last_name:
            raise ValueError(_('A  last_name is required'))
        #creation de l'utilisateur avec ces donnees
        user = self.model(email=email,first_name=first_name,last_name=last_name,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self,email,first_name,last_name,password,**extra_fields):
        extra_fields.setdefault("is_staff",True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("is_staff must be true for admin user"))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("is_superuser must be true for admin user"))
        user = self.create_user(email,first_name,last_name,password,**extra_fields)
        user.save(using=self._db)

        return user







from datetime import datetime
import pytz

from django.contrib.auth.models import User
from django.db import models


# Create your models here.



class Preacher(models.Model):
    name = models.CharField(max_length=5000, blank=True, null=True)
    prenom = models.CharField(max_length=5000, blank=True, null=True)
    email = models.EmailField()
    tel = models.CharField(max_length=5000, blank=True, null=True)

    def __str__(self):
        return f'{self.name} {self.prenom}'


class Sermon(models.Model):
    dateSermon = models.DateField()
    theme = models.CharField(max_length=5000, blank=True, null=True)
    subTheme = models.CharField(max_length=5000, blank=True, null=True)
    bibleVerses = models.CharField(max_length=5000, blank=True, null=True)
    preacher = models.ForeignKey(Preacher, on_delete=models.CASCADE, related_name="preacher")
    link = models.CharField(max_length=5000, blank=True, null=True)
    image = models.ImageField(upload_to="sermons_images/", blank=True, null=True)
    start_time = models.TimeField(blank=True, null=True)
    end_time = models.TimeField(blank=True, null=True)
    date = models.DateTimeField(auto_now=True)

    @property
    def get_hour_and_date(self):
        now = datetime.now(pytz.utc)
        diff = now - self.date
        seconds = diff.total_seconds()

        # Date , jour et second
        days = int(seconds // (24 * 3600))
        hours = int((seconds % (24 * 3600)) // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)

        # formatter
        if days > 0:
            return f'{days}j'
        elif hours > 0:
            return f'{hours}h'
        elif minutes > 0:
            return f'{minutes}min'
        else:
            return f'{seconds} sec'

    def __str__(self):
        return self.theme

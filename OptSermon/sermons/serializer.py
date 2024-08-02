from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import Preacher, Sermon


class PreacherSerializer(serializers.ModelSerializer):
    name = serializers.CharField(max_length=5000, required=False, allow_blank=True)
    prenom = serializers.CharField(max_length=5000, required=False, allow_blank=True)
    tel = serializers.CharField(max_length=5000, required=False, allow_blank=True)

    class Meta:
        model = Preacher
        fields = '__all__'


class SermonSerializer(serializers.ModelSerializer):
    diff_hours = serializers.SerializerMethodField(read_only=True)
    theme = serializers.CharField(max_length=5000, required=False, allow_blank=True)
    subTheme = serializers.CharField(max_length=5000, required=False, allow_blank=True)
    bibleVerses = serializers.CharField(max_length=5000, required=False, allow_blank=True)
    start_time = serializers.TimeField(required=False, allow_null=True)
    end_time = serializers.TimeField(required=False, allow_null=True)

    class Meta:
        model = Sermon
        fields = (
            'pk', 'dateSermon', 'theme', 'subTheme', 'link', 'bibleVerses', 'preacher', 'image', 'start_time',
            'end_time',
            'diff_hours')

    def validate(self, attrs):
        start_time = attrs.get('start_time')
        end_time = attrs.get('end_time')

        if start_time >= end_time:
            raise ValidationError("end_time must not be inferior to start_time")
        return attrs

    def get_diff_hours(self, obj):
        return obj.get_hour_and_date

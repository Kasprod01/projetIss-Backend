from django.shortcuts import render

from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializer import  PreacherSerializer, SermonSerializer
from .models import  Preacher, Sermon


class PreacherViewSet(viewsets.ModelViewSet):
    queryset = Preacher.objects.all()
    serializer_class = PreacherSerializer
    permission_classes = [IsAuthenticated]


class SermonViewSet(viewsets.ModelViewSet):
    queryset = Sermon.objects.all()
    serializer_class = SermonSerializer
    permission_classes = [IsAuthenticated]



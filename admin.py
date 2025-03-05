from django.contrib import admin
from .models import Threat, AutomatedResponse, IncidentReport

admin.site.register(Threat)
admin.site.register(AutomatedResponse)
admin.site.register(IncidentReport)

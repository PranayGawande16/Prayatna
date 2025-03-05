from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now

class Threat(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    type = models.CharField(max_length=255)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    description = models.TextField()

    def __str__(self):
        return f"{self.type} ({self.severity})"

class AutomatedResponse(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    action_taken = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Response to {self.threat.type} - {self.action_taken}"

class IncidentReport(models.Model):
    threat = models.ForeignKey("Threat", on_delete=models.CASCADE)
    report_details = models.TextField()
    generated_at = models.DateTimeField(default=now)
    report_file = models.FileField(upload_to="incident_reports/", blank=True, null=True)
    
    def __str__(self):
        return f"Report for {self.threat.type} at {self.generated_at}"

class AdminActionLog(models.Model):
    admin = models.ForeignKey(User, on_delete=models.CASCADE)
    action_type = models.CharField(max_length=255)
    details = models.TextField()
    timestamp = models.DateTimeField(default=now)
    def __str__(self):
        return f"{self.admin.username} - {self.action_type} at {self.timestamp}"


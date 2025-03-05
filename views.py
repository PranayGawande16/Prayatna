from django.shortcuts import render
from .models import Threat, AutomatedResponse, IncidentReport
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
import subprocess
from .models import IncidentReport
from .models import Threat
from .models import AdminActionLog
from django.contrib.auth.decorators import login_required
from django.conf import settings
import requests
import smtplib
from email.mime.text import MIMEText
import sys
import os

@login_required
def admin_control_panel(request):
    threats = Threat.objects.all().order_by("-timestamp")
    reports = IncidentReport.objects.all().order_by("-generated_at")
    return render(request, "threats/admin_panel.html", {"threats": threats, "reports": reports})

@login_required
def remove_threat(request, threat_id):
    threat = get_object_or_404(Threat, id=threat_id)
    threat_type = threat.type
    source_ip = threat.source_ip
    threat.delete()
    AdminActionLog.objects.create(
        admin=request.user,
        action_type="Removed Threat",
        details=f"Removed threat {threat_type} from {source_ip}"
    )
    messages.success(request, "Threat removed successfully.")
    return redirect("admin_panel")

@login_required
def approve_report(request, report_id):
    report = get_object_or_404(IncidentReport, id=report_id)
    AdminActionLog.objects.create(
        admin=request.user,
        action_type="Approved Report",
        details=f"Approved report for {report.threat.type}"
    )
    messages.success(request, f"Report for {report.threat.type} approved.")
    return redirect("admin_panel")

@login_required
def threat_dashboard(request):
    threats = Threat.objects.all().order_by("-timestamp")
    return render(request, "threats/dashboard.html", {"threats": threats})

def incident_reports(request):
    reports = IncidentReport.objects.all().order_by("-generated_at")
    return render(request, "threats/reports.html", {"reports": reports})

def automated_responses(request):
    responses = AutomatedResponse.objects.all().order_by("-timestamp")
    return render(request, "threats/responses.html", {"responses": responses})


def fetch_threats(request):
    threats = Threat.objects.all().order_by("-timestamp")
    html = render_to_string("threats/threat_table.html", {"threats": threats})
    return JsonResponse(html, safe=False)

@login_required
def block_ip(request, threat_id):
    threat = get_object_or_404(Threat, id=threat_id)
    ip_address = threat.source_ip

    try:
        # Block IP using firewall (Linux example)
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        messages.success(request, f"Blocked IP: {ip_address}")
    except Exception as e:
        messages.error(request, f"Error blocking IP: {e}")

    return redirect("dashboard")

def delete_threat(request, threat_id):
    threat = get_object_or_404(Threat, id=threat_id)
    threat.delete()
    messages.success(request, "Threat deleted successfully.")
    return redirect("dashboard")

@login_required
def block_ip(request, threat_id):
    threat = get_object_or_404(Threat, id=threat_id)
    ip_address = threat.source_ip

    try:
        # Block inbound and outbound traffic
        subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}', shell=True, check=True)
        subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=out action=block remoteip={ip_address}', shell=True, check=True)
        
        messages.success(request, f"Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        messages.error(request, f"Error blocking IP: {e}")

    return redirect("dashboard")

@login_required
def block_ip_admin(request, threat_id):
    threat = get_object_or_404(Threat, id=threat_id)
    ip_address = threat.source_ip

    try:
        command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        # Log the admin action
        AdminActionLog.objects.create(
            admin=request.user,
            action_type="Blocked IP",
            details=f"Blocked IP {ip_address} due to {threat.type}"
        )

        messages.success(request, f"Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        messages.error(request, f"Error blocking IP: {e}. Output: {e.stderr}")

    return redirect("admin_panel") 


def incident_reports(request):
    reports = IncidentReport.objects.all().order_by("-generated_at")
    return render(request, "threats/reports.html", {"reports": reports})

@login_required
def admin_logs(request):
    logs = AdminActionLog.objects.all().order_by("-timestamp")
    return render(request, "threats/admin_logs.html", {"logs": logs})

@login_required
def trigger_log_scan(request):
    try:
        venv_python = os.path.join(sys.prefix, "Scripts", "python.exe")  # Get virtualenv Python path
        result = subprocess.run([venv_python, "manage.py", "back4"], capture_output=True, text=True, check=True)
        messages.success(request, f"Log scan started successfully! Output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        messages.error(request, f"Error triggering log scan: {e}. Output: {e.stderr}")

    return redirect("admin_panel")

@login_required
def send_alerts(request):
    try:
        # Discord Webhook
        discord_webhook_url = "https://discord.com/api/webhooks/1342550617213636628/a16XNcTb4TP-ovIZoP-ATHMfvf4IcQnj-O0TKEP3XcElN8cRKmiiNa6mpx-hOR_ObiWU"
        message = {"content": "🚨 New Threat Detected! Check the dashboard for details."}
        requests.post(discord_webhook_url, json=message)

        # Email Alert
        sender_email = settings.EMAIL_HOST_USER
        receiver_email = "0808cb231043.ies@ipsacademy.org"
        msg = MIMEText("A new cybersecurity threat has been detected. Check the dashboard.")
        msg["Subject"] = "🚨 Cybersecurity Alert"
        msg["From"] = sender_email
        msg["To"] = receiver_email

        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(sender_email, settings.EMAIL_HOST_PASSWORD)
            server.sendmail(sender_email, receiver_email, msg.as_string())

        messages.success(request, "Alerts sent successfully!")
    except Exception as e:
        messages.error(request, f"Error sending alerts: {e}")

    return redirect("admin_panel")


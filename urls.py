from django.urls import path
from .views import send_alerts,trigger_log_scan,admin_logs,admin_control_panel,remove_threat,approve_report,incident_reports,threat_dashboard, incident_reports, automated_responses,fetch_threats,block_ip, delete_threat,block_ip_admin

urlpatterns = [
    path("", threat_dashboard, name="dashboard"),
    path("admin-panel/", admin_control_panel, name="admin_panel"),
    path("remove-threat/<int:threat_id>/", remove_threat, name="remove_threat"),
    path("approve-report/<int:report_id>/", approve_report, name="approve_report"),
    path("block-ip-admin/<int:threat_id>/", block_ip_admin, name="block_ip_admin"),
    path("reports/", incident_reports, name="incident_reports"),
    path("responses/", automated_responses, name="automated_responses"),
    path("fetch-threats/", fetch_threats, name="fetch_threats"),
    path("block-ip/<int:threat_id>/", block_ip, name="block_ip"),
    path("delete-threat/<int:threat_id>/", delete_threat, name="delete_threat"),
    path("admin-logs/", admin_logs, name="admin_logs"),
    path("trigger-log-scan/", trigger_log_scan, name="trigger_log_scan"),
    path("send-alerts/", send_alerts, name="send_alerts"),
]

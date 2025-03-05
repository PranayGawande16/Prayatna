import csv
import os
from django.core.management.base import BaseCommand
from django.utils.timezone import now
from threats.models import Threat, IncidentReport

class Command(BaseCommand):
    help = "Generates an incident report from detected threats"

    def handle(self, *args, **kwargs):
        threats = Threat.objects.all().order_by("-timestamp")
        
        if not threats.exists():
            self.stdout.write(self.style.WARNING("No threats detected. Report not generated."))
            return

        filename = f"incident_report_{now().strftime('%Y%m%d_%H%M%S')}.csv"
        report_path = os.path.join("media/incident_reports", filename)

        os.makedirs("media/incident_reports", exist_ok=True)

        with open(report_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Type", "Severity", "Source IP", "Timestamp"])
            
            for threat in threats:
                writer.writerow([threat.type, threat.severity, threat.source_ip, threat.timestamp])

                # Create a report entry linked to the threat
                IncidentReport.objects.create(
                    threat=threat,  # Assign the threat properly
                    report_details=f"Generated on {now()} for threat: {threat.type}",
                    report_file=f"incident_reports/{filename}"
                )

        self.stdout.write(self.style.SUCCESS(f"Incident report generated: {filename}"))

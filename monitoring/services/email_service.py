from django.core.mail import send_mail
from django.conf import settings

def send_threat_email(threat):

    send_mail(
        subject=f"Threat Detected: {threat.threat_name}",
        message=(
            f"A threat was detected.\n\n"
            f"Name: {threat.threat_name}\n"
            f"Severity: {threat.severity}\n"
            f"Description: {threat.description}"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=["admin@example.com"],
        fail_silently=False,
    )
import os
import sys
import threading

from django.apps import AppConfig


class MonitoringConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "monitoring"

    def ready(self):

        # Don't run on Render
        if os.environ.get("RENDER"):
            print("Render detected - skipping Scapy sniffer")
            return

        # Don't run during management commands
        skip_commands = [
            "makemigrations",
            "migrate",
            "collectstatic",
            "flush",
            "createsuperuser",
            "shell",
            "dbshell",
            "check",
            "test",
            "showmigrations",
        ]

        if any(cmd in sys.argv for cmd in skip_commands):
            return

        from monitoring.services.packet_sniffer import start_sniffer

        def run_sniffer():
            try:
                print("========================================")
                print(" Network Packet Sniffer Started")
                print("========================================")
                start_sniffer()
            except Exception as e:
                print("Sniffer Error:", e)

        threading.Thread(
            target=run_sniffer,
            daemon=True
        ).start()
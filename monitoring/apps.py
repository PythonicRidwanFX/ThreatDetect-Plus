import os
import threading

from django.apps import AppConfig


class MonitoringConfig(AppConfig):

    default_auto_field = "django.db.models.BigAutoField"
    name = "monitoring"


    def ready(self):

        # Prevent running during migrations
        if os.environ.get("RUN_MAIN") != "true":
            return

        from monitoring.services.packet_sniffer import start_sniffer


        def run_sniffer():

            try:
                print("================================")
                print("Starting Network Packet Sniffer...")
                print("================================")

                start_sniffer()

            except Exception as e:
                print("Sniffer Error:", e)


        thread = threading.Thread(
            target=run_sniffer,
            daemon=True
        )

        thread.start()
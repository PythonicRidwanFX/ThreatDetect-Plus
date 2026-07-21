import os
import threading

from django.apps import AppConfig


class MonitoringConfig(AppConfig):

    default_auto_field = "django.db.models.BigAutoField"
    name = "monitoring"


    def ready(self):

        # Do not run packet sniffer on Render
        if os.environ.get("RENDER"):
            print(
                "Render detected - skipping Scapy sniffer"
            )
            return


        from monitoring.services.packet_sniffer import start_sniffer


        def run_sniffer():

            try:

                print(
                    "Starting Network Packet Sniffer..."
                )

                start_sniffer()


            except Exception as e:

                print(
                    "Sniffer Error:",
                    e
                )


        thread = threading.Thread(
            target=run_sniffer,
            daemon=True
        )


        thread.start()
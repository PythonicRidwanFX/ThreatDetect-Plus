import os
import sys
import threading

from django.apps import AppConfig


sniffer_started = False


class MonitoringConfig(AppConfig):

    default_auto_field = "django.db.models.BigAutoField"
    name = "monitoring"


    def ready(self):

        global sniffer_started


        if sniffer_started:
            return


        # Skip management commands
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


        sniffer_started = True


        from monitoring.services.packet_sniffer import start_sniffer


        def run_sniffer():

            print("========================================")
            print(" Network Packet Sniffer Started")
            print("========================================")


            try:

                start_sniffer()


            except PermissionError:

                if os.environ.get("RENDER"):

                    print(
                        "Render does not allow packet capture. "
                        "Sniffer disabled."
                    )

                else:

                    raise


            except Exception as e:

                print(
                    "Sniffer Error:",
                    e
                )


        threading.Thread(
            target=run_sniffer,
            daemon=True
        ).start()
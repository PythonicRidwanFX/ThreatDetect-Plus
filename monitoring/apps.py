import sys
import threading

from django.apps import AppConfig


class MonitoringConfig(AppConfig):

    default_auto_field = "django.db.models.BigAutoField"
    name = "monitoring"


    def ready(self):

        # Prevent duplicate sniffer when Django autoreloader runs
        if "runserver" in sys.argv and "--noreload" not in sys.argv:
            return


        # Don't start sniffer during management commands
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


        if any(
            command in sys.argv
            for command in skip_commands
        ):
            return


        from monitoring.services.packet_sniffer import start_sniffer


        def run_sniffer():

            try:

                print("========================================")
                print(" Network Packet Sniffer Started")
                print("========================================")

                start_sniffer()


            except Exception as e:

                print("========================================")
                print(" Sniffer Error:", e)
                print("========================================")


        sniffer_thread = threading.Thread(
            target=run_sniffer,
            daemon=True
        )


        sniffer_thread.start()
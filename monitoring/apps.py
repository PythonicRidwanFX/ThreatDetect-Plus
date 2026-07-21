import threading

from django.apps import AppConfig


# Prevent duplicate sniffer threads
sniffer_started = False


class MonitoringConfig(AppConfig):

    default_auto_field = "django.db.models.BigAutoField"

    name = "monitoring"


    def ready(self):

        global sniffer_started


        # Avoid starting twice
        if sniffer_started:
            return


        sniffer_started = True



        try:

            from monitoring.services.packet_sniffer import start_sniffer


            def run_sniffer():

                try:

                    print("=" * 40)
                    print("Starting Network Packet Sniffer...")
                    print("=" * 40)


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



        except Exception as e:


            print(
                "Failed to start sniffer:",
                e
            )
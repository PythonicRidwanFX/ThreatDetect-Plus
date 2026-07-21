from django.core.management.base import BaseCommand
from monitoring.services.packet_sniffer import start_sniffer


class Command(BaseCommand):
    help = "Starts the real-time packet sniffer"

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS(
                "======================================"
            )
        )

        self.stdout.write(
            self.style.SUCCESS(
                " ThreatDetect+ Packet Sniffer Started"
            )
        )

        self.stdout.write(
            self.style.SUCCESS(
                " Press CTRL+C to stop monitoring"
            )
        )

        self.stdout.write(
            self.style.SUCCESS(
                "======================================"
            )
        )

        try:
            start_sniffer()

        except KeyboardInterrupt:
            self.stdout.write(
                self.style.WARNING(
                    "Packet sniffer stopped."
                )
            )
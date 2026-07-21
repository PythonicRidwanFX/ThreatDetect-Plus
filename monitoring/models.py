from django.db import models


class PacketLog(models.Model):
    PROTOCOLS = (
        ("TCP", "TCP"),
        ("UDP", "UDP"),
        ("ICMP", "ICMP"),
        ("ARP", "ARP"),
        ("DNS", "DNS"),
        ("HTTP", "HTTP"),
        ("HTTPS", "HTTPS"),
        ("OTHER", "OTHER"),
    )

    DIRECTIONS = (
        ("Incoming", "Incoming"),
        ("Outgoing", "Outgoing"),
        ("Unknown", "Unknown"),
    )

    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_mac = models.CharField(max_length=30, blank=True, null=True)
    destination_mac = models.CharField(max_length=30, blank=True, null=True)
    protocol = models.CharField(max_length=20, choices=PROTOCOLS, default="OTHER")
    source_port = models.PositiveIntegerField(blank=True, null=True)
    destination_port = models.PositiveIntegerField(blank=True, null=True)
    tcp_flags = models.CharField(max_length=50, blank=True, null=True)
    ttl = models.PositiveIntegerField(blank=True, null=True)
    packet_length = models.PositiveIntegerField()
    interface = models.CharField(max_length=100, default="Unknown")
    direction = models.CharField(max_length=20, choices=DIRECTIONS, default="Unknown")
    captured_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-captured_at"]

    def __str__(self):
        return f"{self.source_ip} → {self.destination_ip}"


class Threat(models.Model):
    SEVERITY = (
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    )

    STATUS = (
        ("New", "New"),
        ("Investigating", "Investigating"),
        ("Resolved", "Resolved"),
    )

    packet = models.ForeignKey(PacketLog, on_delete=models.CASCADE, related_name="threats")
    threat_name = models.CharField(max_length=150)
    severity = models.CharField(max_length=20, choices=SEVERITY)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS, default="New")
    detected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.threat_name


class Alert(models.Model):
    ALERT_TYPES = (
        ("Dashboard", "Dashboard"),
        ("Email", "Email"),
        ("SMS", "SMS"),
    )

    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES, default="Dashboard")
    message = models.TextField()
    sent = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.message[:50]


class SystemStatus(models.Model):
    packet_capture = models.BooleanField(default=False)
    threat_detection = models.BooleanField(default=False)
    alert_engine = models.BooleanField(default=False)
    machine_learning = models.BooleanField(default=False)
    packets_today = models.PositiveIntegerField(default=0)
    threats_today = models.PositiveIntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "ThreatDetect+ Status"

class Prediction(models.Model):
    packet = models.ForeignKey(
        PacketLog,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    attack_type = models.CharField(max_length=100)

    status = models.CharField(max_length=20)

    confidence = models.FloatField()

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.attack_type} ({self.confidence:.2f}%)"
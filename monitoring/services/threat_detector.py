from collections import defaultdict
from datetime import datetime, timedelta

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from monitoring.models import Threat, Alert, Prediction
from monitoring.models import Threat, Alert
from monitoring.services.feature_extractor import extract_features
from monitoring.services.ml_detector import predict
from monitoring.services.feature_extractor import (
    extract_features,
    flows,
)

connection_cache = defaultdict(list)
icmp_cache = defaultdict(list)

SUSPICIOUS_PORTS = {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 3389}
BLACKLIST = {"192.168.1.200", "10.10.10.10"}


def broadcast(event_type, payload):

    channel_layer = get_channel_layer()

    counts = get_security_counts()

    async_to_sync(channel_layer.group_send)(
        "dashboard",
        {
            "type": "dashboard_update",
            "data": {
                "event": event_type,

                **payload,

                # live counters
                **counts,
            },
        },
    )

def get_security_counts():

    return {

        "total_threats": Threat.objects.count(),

        "total_alerts": Alert.objects.count(),

        "critical_count": Threat.objects.filter(
            severity="Critical"
        ).count(),

        "high_count": Threat.objects.filter(
            severity="High"
        ).count(),

        "medium_count": Threat.objects.filter(
            severity="Medium"
        ).count(),

        "low_count": Threat.objects.filter(
            severity="Low"
        ).count(),

    }

def create_threat(packet, name, severity, description):


    if Threat.objects.filter(
        packet=packet,
        threat_name=name
    ).exists():

        return



    threat = Threat.objects.create(

        packet=packet,

        threat_name=name,

        severity=severity,

        description=description,

    )



    alert = Alert.objects.create(

        threat=threat,

        alert_type="Dashboard",

        message=description,

        sent=False,

    )



    # Threat Detection Page

    broadcast(

        "threat_detected",

        {

            "time":
            threat.detected_at.strftime("%H:%M:%S"),


            "name":
            threat.threat_name,


            "severity":
            threat.severity,


            "message":
            threat.description,


            "source_ip":
            packet.source_ip,

        }

    )



    # Alert Page

    broadcast(
        "security_alert",
        {
            "id": alert.id,

            "time": alert.created_at.strftime("%H:%M:%S"),

            "name": threat.threat_name,

            "severity": threat.severity,

            "message": alert.message,

            "source_ip": packet.source_ip,

            "destination_ip": packet.destination_ip,

            "protocol": packet.protocol,

            "status": threat.status,

            "confidence": getattr(threat, "confidence", 0),

            "total_threats": Threat.objects.count(),

            "total_alerts": Alert.objects.count(),
        }
    )

def detect_blacklist(packet):
    if packet.source_ip in BLACKLIST:
        create_threat(
            packet,
            "Blacklisted IP",
            "Critical",
            f"Traffic from blacklisted IP {packet.source_ip}",
        )


def detect_sensitive_ports(packet):
    if packet.destination_port in SUSPICIOUS_PORTS:
        create_threat(
            packet,
            "Sensitive Port Access",
            "Medium",
            f"Access to sensitive port {packet.destination_port}",
        )


def detect_icmp(packet):

    if packet.protocol != "ICMP":
        return

    now = datetime.now()

    icmp_cache[packet.source_ip].append(now)

    icmp_cache[packet.source_ip] = [
        t
        for t in icmp_cache[packet.source_ip]
        if now - t < timedelta(seconds=5)
    ]

    if len(icmp_cache[packet.source_ip]) >= 20:

        create_threat(
            packet,
            "ICMP Flood",
            "High",
            f"ICMP Flood detected from {packet.source_ip}",
        )

        icmp_cache[packet.source_ip].clear()


def detect_port_scan(packet):

    if packet.destination_port is None:
        return

    now = datetime.now()

    connection_cache[packet.source_ip].append(
        (
            packet.destination_port,
            now
        )
    )

    connection_cache[packet.source_ip] = [
        x
        for x in connection_cache[packet.source_ip]
        if now - x[1] < timedelta(seconds=10)
    ]

    unique_ports = {
        port
        for port, _
        in connection_cache[packet.source_ip]
    }

    if len(unique_ports) >= 10:

        create_threat(
            packet,
            "Port Scan",
            "Critical",
            f"Possible port scan from {packet.source_ip}",
        )

        connection_cache[packet.source_ip].clear()

def detect_machine_learning(packet):
    """
    Detect attacks using Random Forest model.
    """

    try:

        print("=" * 70)
        print("ML DETECTOR")
        print(
            f"{packet.source_ip}:{packet.source_port} "
            f"-> "
            f"{packet.destination_ip}:{packet.destination_port}"
        )

        print("Protocol:", packet.protocol)
        print("Flows Before:", len(flows))

        features = extract_features(packet)

        print("Flows After :", len(flows))

        print(
            "Forward:",
            features["Total Fwd Packets"],
            "Backward:",
            features["Total Backward Packets"],
        )

        result = predict(features)

        print("\n" + "=" * 60)
        print("Prediction Probabilities")
        print("=" * 60)

        for attack, score in sorted(
                result["probabilities"].items(),
                key=lambda x: x[1],
                reverse=True
        ):
            print(f"{attack:30} {score:.2f}%")

        print("=" * 70)

        print("\n")
        print("=" * 70)
        print("ML RESULT")
        print("=" * 70)
        print(f"Prediction : {result['label']}")
        print(f"Confidence : {result['confidence']:.2f}%")
        print(f"Attack     : {result['attack']}")
        print("=" * 70)

        Prediction.objects.create(
            packet=packet,
            attack_type=result["label"],
            is_attack=result["attack"],
            confidence=result["confidence"],
            model_name="Random Forest",
        )

        if result["attack"]:

            attack_name = result["label"]
            confidence = result["confidence"]

            if attack_name in (
                "DDoS",
                "DoS Hulk",
                "DoS GoldenEye",
                "Infiltration",
            ):
                severity = "Critical"

            elif attack_name in (
                "PortScan",
                "Bot",
                "FTP-Patator",
                "SSH-Patator",
            ):
                severity = "High"

            else:
                severity = "Medium"

            create_threat(
                packet,
                attack_name,
                severity,
                f"Machine Learning detected {attack_name}. Confidence: {confidence:.2f}%"
            )

    except Exception as e:
        print("=" * 70)
        print("ML Detection Error")
        print(e)

def detect(packet):

    detect_blacklist(packet)

    detect_sensitive_ports(packet)

    detect_icmp(packet)

    detect_port_scan(packet)

    detect_machine_learning(packet)
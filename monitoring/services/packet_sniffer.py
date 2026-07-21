from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models import Count, Q
from monitoring.models import (
    PacketLog,
    SystemStatus,
)

from monitoring.services.threat_detector import detect

import socket


# ==========================================================
# WEBSOCKET BROADCAST
# ==========================================================

def broadcast_packet(event_type, payload):
    channel_layer = get_channel_layer()

    async_to_sync(channel_layer.group_send)(
        "dashboard",
        {
            "type": "dashboard_update",
            "data": {
                "event": event_type,
                **payload,
            },
        },
    )


# ==========================================================
# SYSTEM STATUS
# ==========================================================

def update_system_status():
    status, created = SystemStatus.objects.get_or_create(id=1)

    status.packet_capture = True
    status.threat_detection = True
    status.machine_learning = True
    status.alert_engine = True

    status.save()


def increase_packet_count():
    status, created = SystemStatus.objects.get_or_create(id=1)

    status.packets_today += 1
    status.save()


# ==========================================================
# DETERMINE PACKET DIRECTION
# ==========================================================

def get_direction(src_ip):
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        if src_ip == local_ip:
            return "Outgoing"

        return "Incoming"

    except Exception:
        return "Unknown"


# ==========================================================
# SAVE PACKET
# ==========================================================

def save_packet(packet):
    try:

        if IP not in packet:
            return

        protocol = "OTHER"
        sport = None
        dport = None
        flags = None

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = str(packet[TCP].flags)

        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        src_mac = packet[Ether].src if Ether in packet else ""
        dst_mac = packet[Ether].dst if Ether in packet else ""

        direction = get_direction(packet[IP].src)

        packet_obj = PacketLog.objects.create(
            source_ip=packet[IP].src,
            destination_ip=packet[IP].dst,
            source_mac=src_mac,
            destination_mac=dst_mac,
            protocol=protocol,
            source_port=sport,
            destination_port=dport,
            tcp_flags=flags,
            ttl=packet[IP].ttl,
            packet_length=len(packet),
            interface="Default",
            direction=direction,
        )

        increase_packet_count()

        status = SystemStatus.objects.get(id=1)

        packet_stats = PacketLog.objects.aggregate(
            total=Count("id"),
            tcp=Count("id", filter=Q(protocol="TCP")),
            udp=Count("id", filter=Q(protocol="UDP")),
            icmp=Count("id", filter=Q(protocol="ICMP")),
        )

        other_packets = (
            PacketLog.objects
            .exclude(protocol__in=["TCP", "UDP", "ICMP"])
            .count()
        )

        broadcast_packet(
            "packet",
            {
                "time": packet_obj.captured_at.strftime("%H:%M:%S"),
                "source_ip": packet_obj.source_ip,
                "destination_ip": packet_obj.destination_ip,
                "protocol": packet_obj.protocol,
                "packet_length": packet_obj.packet_length,
                "direction": packet_obj.direction,
                "interface": packet_obj.interface,

                # Dashboard Counters
                "total_packets": packet_stats["total"] or 0,
                "tcp_packets": packet_stats["tcp"] or 0,
                "udp_packets": packet_stats["udp"] or 0,
                "icmp_packets": packet_stats["icmp"] or 0,
                "other_packets": other_packets,
                "packets_today": status.packets_today,
            },
        )

        # Run Threat Detection
        detect(packet_obj)

    except Exception as e:
        print("Packet Capture Error:", e)


# ==========================================================
# START SNIFFER
# ==========================================================

def start_sniffer(interface=None):
    print("=" * 40)
    print(" Network Packet Sniffer Started ")
    print("=" * 40)

    update_system_status()

    sniff(
        iface=interface,
        prn=save_packet,
        store=False,
    )
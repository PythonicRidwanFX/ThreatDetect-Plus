import time
from collections import defaultdict

import numpy as np


# Store flow information
flows = defaultdict(list)


def get_flow_key(packet):
    """
    Creates a unique network flow key.
    """

    return (
        packet.source_ip,
        packet.destination_ip,
        packet.source_port,
        packet.destination_port,
        packet.protocol,
    )


def extract_features(packet):
    """
    Convert captured packets into CIC-IDS style features.

    Returns a dictionary that matches the ML model input.
    """

    key = get_flow_key(packet)

    now = time.time()

    flows[key].append(
        {
            "time": now,
            "length": packet.packet_length,
        }
    )


    packets = flows[key]


    lengths = [
        p["length"]
        for p in packets
    ]


    duration = (
        packets[-1]["time"]
        -
        packets[0]["time"]
    )


    if duration == 0:
        duration = 1



    total_packets = len(packets)

    total_bytes = sum(lengths)



    features = {

        "Destination Port": packet.destination_port or 0,

        "Flow Duration": duration,

        "Total Fwd Packets": total_packets,

        "Total Backward Packets": 0,

        "Total Length of Fwd Packets": total_bytes,

        "Total Length of Bwd Packets": 0,


        "Fwd Packet Length Max": max(lengths),

        "Fwd Packet Length Min": min(lengths),

        "Fwd Packet Length Mean":
            np.mean(lengths),

        "Fwd Packet Length Std":
            np.std(lengths),


        "Bwd Packet Length Max": 0,

        "Bwd Packet Length Min": 0,

        "Bwd Packet Length Mean": 0,

        "Bwd Packet Length Std": 0,


        "Flow Bytes/s":
            total_bytes / duration,


        "Flow Packets/s":
            total_packets / duration,


        "Packet Length Mean":
            np.mean(lengths),

        "Packet Length Std":
            np.std(lengths),

        "Packet Length Variance":
            np.var(lengths),


        "Min Packet Length":
            min(lengths),

        "Max Packet Length":
            max(lengths),


        "Average Packet Size":
            np.mean(lengths),


        "SYN Flag Count": 0,

        "ACK Flag Count": 0,

        "FIN Flag Count": 0,

        "RST Flag Count": 0,

        "PSH Flag Count": 0,

        "URG Flag Count": 0,


        "Init_Win_bytes_forward": 0,

        "Init_Win_bytes_backward": 0,


        "Active Mean": 0,

        "Active Std": 0,

        "Active Max": 0,

        "Active Min": 0,


        "Idle Mean": 0,

        "Idle Std": 0,

        "Idle Max": 0,

        "Idle Min": 0,

    }


    return features
import time
import statistics

from collections import defaultdict


# ==========================================================
# FLOW CONFIGURATION
# ==========================================================

FLOW_TIMEOUT = 60

HEADER_TCP = 40
HEADER_UDP = 28
HEADER_ICMP = 28
HEADER_OTHER = 20


# ==========================================================
# FLOW STORAGE
# ==========================================================

flows = defaultdict(
    lambda: {

        "start_time": None,
        "last_time": None,

        "forward_packets": [],
        "forward_lengths": [],
        "forward_header_lengths": [],
        "forward_iat": [],
        "forward_bytes": 0,

        "backward_packets": [],
        "backward_lengths": [],
        "backward_header_lengths": [],
        "backward_iat": [],
        "backward_bytes": 0,

        "flow_iat": [],

        "syn": 0,
        "ack": 0,
        "fin": 0,
        "rst": 0,
        "psh": 0,
        "urg": 0,
        "ece": 0,
        "cwe": 0,

        "active_times": [],
        "idle_times": [],

        "client_ip": None,
        "server_ip": None,
        "client_port": None,
        "server_port": None,
    }
)


# ==========================================================
# SAFE FUNCTIONS
# ==========================================================

def safe_mean(values):

    if not values:
        return 0

    return float(statistics.mean(values))


def safe_std(values):

    if len(values) < 2:
        return 0

    return float(statistics.stdev(values))


def safe_variance(values):

    if len(values) < 2:
        return 0

    return float(statistics.variance(values))


def safe_max(values):

    if not values:
        return 0

    return max(values)


def safe_min(values):

    if not values:
        return 0

    return min(values)


# ==========================================================
# FLOW KEY
# ==========================================================

def get_flow_key(packet):

    ip_pair = tuple(sorted([
        packet.source_ip,
        packet.destination_ip,
    ]))

    port_pair = tuple(sorted([
        packet.source_port or 0,
        packet.destination_port or 0,
    ]))

    return (
        ip_pair,
        port_pair,
        packet.protocol,
    )


# ==========================================================
# FLOW CLEANUP
# ==========================================================

def cleanup_flows():

    now = time.time()

    expired = []

    for key, flow in flows.items():

        if flow["last_time"] is None:
            continue

        if now - flow["last_time"] > FLOW_TIMEOUT:
            expired.append(key)

    for key in expired:
        del flows[key]


# ==========================================================
# HEADER LENGTH
# ==========================================================

def get_header_length(packet):

    if packet.protocol == "TCP":
        return HEADER_TCP

    if packet.protocol == "UDP":
        return HEADER_UDP

    if packet.protocol == "ICMP":
        return HEADER_ICMP

    return HEADER_OTHER
# ==========================================================
# SAFE STATISTICS
# ==========================================================

def safe_mean(values):
    if not values:
        return 0
    return statistics.mean(values)


def safe_std(values):
    if len(values) < 2:
        return 0
    return statistics.stdev(values)


def safe_variance(values):
    if len(values) < 2:
        return 0
    return statistics.variance(values)


def safe_max(values):
    if not values:
        return 0
    return max(values)


def safe_min(values):
    if not values:
        return 0
    return min(values)


# ==========================================================
# FLOW DURATION
# ==========================================================

def get_flow_duration(flow):

    duration = flow["last_time"] - flow["start_time"]

    if duration <= 0:
        duration = 1e-6

    return duration


# ==========================================================
# UPDATE TCP FLAGS
# ==========================================================

def update_tcp_flags(flow, packet):

    flags = str(packet.tcp_flags or "").upper()

    if "S" in flags:
        flow["syn"] += 1

    if "A" in flags:
        flow["ack"] += 1

    if "F" in flags:
        flow["fin"] += 1

    if "R" in flags:
        flow["rst"] += 1

    if "P" in flags:
        flow["psh"] += 1

    if "U" in flags:
        flow["urg"] += 1

    if "E" in flags:
        flow["ece"] += 1

    if "C" in flags:
        flow["cwe"] += 1


# ==========================================================
# UPDATE IDLE TIMES
# ==========================================================

def update_idle_times(flow):

    if len(flow["flow_iat"]) < 2:
        return

    idle = flow["flow_iat"][-1]

    if idle > 1:
        flow["idle_times"].append(idle)


# ==========================================================
# FEATURE EXTRACTION
# ==========================================================

def extract_features(packet):

    cleanup_flows()

    flow = process_packet(packet)

    duration = get_flow_duration(flow)

    fwd = flow["forward_lengths"]
    bwd = flow["backward_lengths"]

    all_lengths = fwd + bwd

    if not all_lengths:
        all_lengths = [0]

    total_packets = len(fwd) + len(bwd)

    total_bytes = (
        flow["forward_bytes"] +
        flow["backward_bytes"]
    )

    return {

        "Destination Port": packet.destination_port or 0,

        "Flow Duration": duration,

        "Total Fwd Packets": len(fwd),

        "Total Backward Packets": len(bwd),

        "Total Length of Fwd Packets": flow["forward_bytes"],

        "Total Length of Bwd Packets": flow["backward_bytes"],

        "Fwd Packet Length Max": safe_max(fwd),

        "Fwd Packet Length Min": safe_min(fwd),

        "Fwd Packet Length Mean": safe_mean(fwd),

        "Fwd Packet Length Std": safe_std(fwd),

        "Bwd Packet Length Max": safe_max(bwd),

        "Bwd Packet Length Min": safe_min(bwd),

        "Bwd Packet Length Mean": safe_mean(bwd),

        "Bwd Packet Length Std": safe_std(bwd),

        "Flow Bytes/s": total_bytes / duration,

        "Flow Packets/s": total_packets / duration,

        "Flow IAT Mean": safe_mean(flow["flow_iat"]),

        "Flow IAT Std": safe_std(flow["flow_iat"]),

        "Flow IAT Max": safe_max(flow["flow_iat"]),

        "Flow IAT Min": safe_min(flow["flow_iat"]),

        "Fwd IAT Total": sum(flow["forward_iat"]),

        "Fwd IAT Mean": safe_mean(flow["forward_iat"]),

        "Fwd IAT Std": safe_std(flow["forward_iat"]),

        "Fwd IAT Max": safe_max(flow["forward_iat"]),

        "Fwd IAT Min": safe_min(flow["forward_iat"]),

        "Bwd IAT Total": sum(flow["backward_iat"]),

        "Bwd IAT Mean": safe_mean(flow["backward_iat"]),

        "Bwd IAT Std": safe_std(flow["backward_iat"]),

        "Bwd IAT Max": safe_max(flow["backward_iat"]),

        "Bwd IAT Min": safe_min(flow["backward_iat"]),

        "Fwd PSH Flags": flow["psh"],

        "Bwd PSH Flags": 0,

        "Fwd URG Flags": flow["urg"],

        "Bwd URG Flags": 0,

        "Fwd Header Length": sum(flow["forward_header_lengths"]),

        "Bwd Header Length": sum(flow["backward_header_lengths"]),

        "Fwd Packets/s": len(fwd) / duration,

        "Bwd Packets/s": len(bwd) / duration,

        "Min Packet Length": safe_min(all_lengths),

        "Max Packet Length": safe_max(all_lengths),

        "Packet Length Mean": safe_mean(all_lengths),

        "Packet Length Std": safe_std(all_lengths),

        "Packet Length Variance": safe_variance(all_lengths),

        "FIN Flag Count": flow["fin"],

        "SYN Flag Count": flow["syn"],

        "RST Flag Count": flow["rst"],

        "PSH Flag Count": flow["psh"],

        "ACK Flag Count": flow["ack"],

        "URG Flag Count": flow["urg"],

        "CWE Flag Count": flow["cwe"],

        "ECE Flag Count": flow["ece"],

        "Down/Up Ratio": len(bwd) / (len(fwd) + 1),

        "Average Packet Size": safe_mean(all_lengths),

        "Avg Fwd Segment Size": safe_mean(fwd),

        "Avg Bwd Segment Size": safe_mean(bwd),

        "Fwd Header Length.1": sum(flow["forward_header_lengths"]),

        "Fwd Avg Bytes/Bulk": 0,

        "Fwd Avg Packets/Bulk": 0,

        "Fwd Avg Bulk Rate": 0,

        "Bwd Avg Bytes/Bulk": 0,

        "Bwd Avg Packets/Bulk": 0,

        "Bwd Avg Bulk Rate": 0,

        "Subflow Fwd Packets": len(fwd),

        "Subflow Fwd Bytes": flow["forward_bytes"],

        "Subflow Bwd Packets": len(bwd),

        "Subflow Bwd Bytes": flow["backward_bytes"],

        "Init_Win_bytes_forward": 0,

        "Init_Win_bytes_backward": 0,

        "act_data_pkt_fwd": len(fwd),

        "min_seg_size_forward": safe_min(fwd),

        "Active Mean": safe_mean(flow["active_times"]),

        "Active Std": safe_std(flow["active_times"]),

        "Active Max": safe_max(flow["active_times"]),

        "Active Min": safe_min(flow["active_times"]),

        "Idle Mean": safe_mean(flow["idle_times"]),

        "Idle Std": safe_std(flow["idle_times"]),

        "Idle Max": safe_max(flow["idle_times"]),

        "Idle Min": safe_min(flow["idle_times"]),

    }
# ==========================================================
# FLOW DEBUGGING
# ==========================================================

def flow_statistics():

    return {

        "active_flows": len(flows),

        "flows": [

            {

                "key": str(key),

                "forward_packets": len(flow["forward_packets"]),

                "backward_packets": len(flow["backward_packets"]),

                "forward_bytes": flow["forward_bytes"],

                "backward_bytes": flow["backward_bytes"],

                "duration": (
                    flow["last_time"] - flow["start_time"]
                    if flow["start_time"] is not None
                    else 0
                ),

            }

            for key, flow in flows.items()

        ],

    }


# ==========================================================
# RESET FLOWS
# ==========================================================

def reset_flows():

    flows.clear()


# ==========================================================
# GET SINGLE FLOW
# ==========================================================

def get_flow(packet):

    key = get_flow_key(packet)

    return flows.get(key)


# ==========================================================
# PRINT FLOW
# ==========================================================

def print_flow(packet):

    flow = get_flow(packet)

    if not flow:

        print("Flow not found.")

        return

    print("=" * 60)

    print("Forward Packets :", len(flow["forward_packets"]))

    print("Backward Packets:", len(flow["backward_packets"]))

    print("Forward Bytes   :", flow["forward_bytes"])

    print("Backward Bytes  :", flow["backward_bytes"])

    print("Duration        :", get_flow_duration(flow))

    print("SYN :", flow["syn"])

    print("ACK :", flow["ack"])

    print("FIN :", flow["fin"])

    print("RST :", flow["rst"])

    print("PSH :", flow["psh"])

    print("URG :", flow["urg"])

    print("=" * 60)

# ==========================================================
# PROCESS PACKET
# ==========================================================

def process_packet(packet):

    key = get_flow_key(packet)

    flow = flows[key]

    now = time.time()

    if flow["start_time"] is None:

        flow["start_time"] = now

        flow["client_ip"] = packet.source_ip
        flow["server_ip"] = packet.destination_ip

        flow["client_port"] = packet.source_port
        flow["server_port"] = packet.destination_port

    packet._capture_time = now

    header_length = get_header_length(packet)

    packet_length = packet.packet_length

    if (
        packet.source_ip == flow["client_ip"]
        and
        packet.destination_ip == flow["server_ip"]
    ):

        flow["forward_packets"].append(packet)

        flow["forward_lengths"].append(packet_length)

        flow["forward_header_lengths"].append(header_length)

        flow["forward_bytes"] += packet_length

        if len(flow["forward_packets"]) > 1:

            previous = flow["forward_packets"][-2]

            flow["forward_iat"].append(
                now - previous._capture_time
            )

    else:

        flow["backward_packets"].append(packet)

        flow["backward_lengths"].append(packet_length)

        flow["backward_header_lengths"].append(header_length)

        flow["backward_bytes"] += packet_length

        if len(flow["backward_packets"]) > 1:

            previous = flow["backward_packets"][-2]

            flow["backward_iat"].append(
                now - previous._capture_time
            )

    if flow["last_time"] is not None:

        flow["flow_iat"].append(
            now - flow["last_time"]
        )

    flow["last_time"] = now

    flow["active_times"].append(
        now - flow["start_time"]
    )

    update_idle_times(flow)

    if packet.protocol == "TCP":

        update_tcp_flags(flow, packet)

    return flow
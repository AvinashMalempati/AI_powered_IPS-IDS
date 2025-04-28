import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict


def extract_pcap_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp or udp")  # Capture TCP/UDP packets
    flows = defaultdict(lambda: {
        "src_ip": "", "dst_ip": "", "protocol": "", "Destination Port": 0, "Flow Duration": 0, "Total Fwd Packets": 0, "Total Backward Packets": 0,
        "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0, "Flow Bytes/s": 0,
        "Flow Packets/s": 0, "Flow IAT Mean": 0, "Flow IAT Std": 0, "Flow IAT Max": 0, "Flow IAT Min": 0,
        "Fwd IAT Total": 0, "Fwd IAT Mean": 0, "Fwd IAT Std": 0, "Fwd IAT Max": 0, "Fwd IAT Min": 0,
        "Bwd IAT Total": 0, "Bwd IAT Mean": 0, "Bwd IAT Std": 0, "Bwd IAT Max": 0, "Bwd IAT Min": 0,
        "Fwd Packet Length Max": 0, "Fwd Packet Length Min": float('inf'), "Fwd Packet Length Mean": 0,
        "Fwd Packet Length Std": 0,
        "Bwd Packet Length Max": 0, "Bwd Packet Length Min": float('inf'), "Bwd Packet Length Mean": 0,
        "Bwd Packet Length Std": 0, "Fwd PSH Flags": 0, "Fwd Header Length": 0, "Bwd Header Length": 0,
        "Fwd Packets/s": 0, "Bwd Packets/s": 0,
        "Packet Length Min": float('inf'), "Packet Length Max": 0, "Packet Length Mean": 0, "Packet Length Std": 0,
        "Packet Length Variance": 0, "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
        "PSH Flag Count": 0, "ACK Flag Count": 0, "URG Flag Count": 0, "ECE Flag Count": 0,
        "Down/Up Ratio": 0, "Avg Packet Size": 0, "Avg Fwd Segment Size": 0, "Avg Bwd Segment Size": 0,
        "Subflow Fwd Packets": 0, "Subflow Bwd Packets": 0, "Subflow Fwd Bytes": 0, "Subflow Bwd Bytes": 0,
        "Init Fwd Win Bytes": 0, "Init Bwd Win Bytes": 0, "Fwd Act Data Packets": 0, "Fwd Seg Size Min": float('inf'),
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0,
        "Idle Max": 0, "Idle Min": 0,
        "Packet Timestamps": [], "Fwd Packet Timestamps": [], "Bwd Packet Timestamps": [],
        "Fwd Packet Sizes": [], "Bwd Packet Sizes": [], "Flow Start Time": None
    })

    # Parse packets and calculate flow features
    for packet in cap:
        try:
            # Extract flow identifier (SrcIP, DstIP, DstPort, Protocol)
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            dst_port = packet[packet.transport_layer].dstport
            protocol = packet.transport_layer
            flow_id = f"{src_ip}-{dst_ip}-{dst_port}-{protocol}"

            timestamp = float(packet.sniff_time.timestamp())
            packet_length = int(packet.length)

            if flow_id not in flows:
                flows[flow_id]["src_ip"] = src_ip
                flows[flow_id]["dst_ip"] = dst_ip
                flows[flow_id]["protocol"] = protocol
                flows[flow_id]["Destination Port"] = int(dst_port)
                flows[flow_id]["Flow Start Time"] = timestamp

            # Update flow statistics
            flow = flows[flow_id]
            flow["Packet Timestamps"].append(timestamp)
            flow["Flow Duration"] = timestamp - flow["Flow Start Time"]

            # Check for Forward or Backward
            if packet.ip.src == src_ip:
                flow["Total Fwd Packets"] += 1
                flow["Fwd Packets Length Total"] += packet_length
                flow["Fwd Packet Sizes"].append(packet_length)
                flow["Fwd Packet Timestamps"].append(timestamp)
                flow["Fwd Packet Length Max"] = max(flow["Fwd Packet Length Max"], packet_length)
                flow["Fwd Packet Length Min"] = min(flow["Fwd Packet Length Min"], packet_length)

                # Check if packet has application data (no headers only)
                if packet_length > 0:
                    flow["Fwd Act Data Packets"] += 1

                # Check for PSH flag and TCP header length
                if "TCP" in packet:
                    flow["Fwd PSH Flags"] += int("P" in packet.tcp.flags)
                    flow["Fwd Header Length"] += int(packet.tcp.hdr_len)

            else:
                flow["Total Backward Packets"] += 1
                flow["Bwd Packets Length Total"] += packet_length
                flow["Bwd Packet Sizes"].append(packet_length)
                flow["Bwd Packet Timestamps"].append(timestamp)
                flow["Bwd Packet Length Max"] = max(flow["Bwd Packet Length Max"], packet_length)
                flow["Bwd Packet Length Min"] = min(flow["Bwd Packet Length Min"], packet_length)

                # Check TCP header length
                if "TCP" in packet:
                    flow["Bwd Header Length"] += int(packet.tcp.hdr_len)

            # Update packet length statistics
            flow["Packet Length Min"] = min(flow["Packet Length Min"], packet_length)
            flow["Packet Length Max"] = max(flow["Packet Length Max"], packet_length)

        except AttributeError:
            continue

    # Process extracted flow features
    flow_data = []
    for flow_id, data in flows.items():
        timestamps = np.array(sorted(data["Packet Timestamps"]))
        fwd_timestamps = np.array(sorted(data["Fwd Packet Timestamps"]))
        bwd_timestamps = np.array(sorted(data["Bwd Packet Timestamps"]))
        lengths = data["Fwd Packet Sizes"] + data["Bwd Packet Sizes"]
        flow_duration = data["Flow Duration"] + 1e-6  # Avoid division by zero

        # Compute overall packet-related statistics
        data["Packet Length Mean"] = np.mean(lengths) if lengths else 0
        data["Packet Length Std"] = np.std(lengths) if lengths else 0
        data["Packet Length Variance"] = np.var(lengths) if lengths else 0

        # Compute flow-level statistics
        data["Flow Bytes/s"] = (data["Fwd Packets Length Total"] + data["Bwd Packets Length Total"]) / flow_duration
        data["Flow Packets/s"] = len(timestamps) / flow_duration
        data["Fwd Packets/s"] = data["Total Fwd Packets"] / flow_duration
        data["Bwd Packets/s"] = data["Total Backward Packets"] / flow_duration

        # Compute flow IAT statistics
        iat = np.diff(timestamps) if len(timestamps) > 1 else [0]
        data["Flow IAT Mean"] = np.mean(iat)
        data["Flow IAT Std"] = np.std(iat)
        data["Flow IAT Max"] = np.max(iat)
        data["Flow IAT Min"] = np.min(iat)

        # Compute Fwd/Bwd IAT statistics
        fwd_iat = np.diff(fwd_timestamps) if len(fwd_timestamps) > 1 else [0]
        bwd_iat = np.diff(bwd_timestamps) if len(bwd_timestamps) > 1 else [0]
        data["Fwd IAT Total"] = np.sum(fwd_iat)
        data["Fwd IAT Mean"] = np.mean(fwd_iat)
        data["Fwd IAT Std"] = np.std(fwd_iat)
        data["Fwd IAT Max"] = np.max(fwd_iat)
        data["Fwd IAT Min"] = np.min(fwd_iat)
        data["Bwd IAT Total"] = np.sum(bwd_iat)
        data["Bwd IAT Mean"] = np.mean(bwd_iat)
        data["Bwd IAT Std"] = np.std(bwd_iat)
        data["Bwd IAT Max"] = np.max(bwd_iat)
        data["Bwd IAT Min"] = np.min(bwd_iat)

        # Update minimum forward segment size
        data["Fwd Seg Size Min"] = min(data["Fwd Packet Sizes"]) if data["Fwd Packet Sizes"] else 0

        # Append the entry to the flow_data
        flow_entry = data.copy()
        flow_data.append(flow_entry)
    df=pd.DataFrame(flow_data)
    df = df[[
        "src_ip", "dst_ip", "protocol", "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max", "Fwd Packet Length Min",
        "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
        "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
        "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
        "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
        "ECE Flag Count", "Down/Up Ratio", "Avg Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
        "Init Fwd Win Bytes", "Init Bwd Win Bytes", "Fwd Act Data Packets", "Fwd Seg Size Min", "Active Mean",
        "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
    ]]

    df.replace([np.inf, -np.inf], 0, inplace=True)
    return df


''''# Run feature extraction
pcap_file = "/Users/avinash/Documents/Thursday-WorkingHours.pcap"
df = extract_pcap_features(pcap_file)


# Save extracted features to CSV, replacing 'inf' and '-inf' values
output_file = "extracted_features.csv"



# Save the DataFrame to a CSV file
df.to_csv(output_file, index=False)
print(f"Feature extraction complete! Data saved to {output_file}.")'''

import tensorflow as tf
import asyncio
import os
from flask import Flask, render_template, request, jsonify
from scapy.all import sniff, get_if_list
from scapy.utils import PcapWriter, wrpcap, RawPcapReader
import pandas as pd
import numpy as np
import threading
import joblib
import time
from extract_features import extract_pcap_features

# Flask app instance
app = Flask(__name__)

# Paths to models and scaler
RF_MODEL_PATH = "models/random_forest_multiclass.joblib"
NN_MODEL_PATH = "models/neural_network_multiclass.h5"

# Load models and scaler
rf_model = joblib.load(RF_MODEL_PATH)
nn_model = tf.keras.models.load_model(NN_MODEL_PATH)

# Global variables for packet capturing
capturing = False
processed_packets = []  # Store the processed packets for the frontend
packet_buffer = []  # Buffer for live packet capturing
BATCH_SIZE = 100  # Number of packets to process as one batch

# Attack type mapping
ATTACK_TYPES = {
    0: "Benign",
    1: "DDoS",
    2: "Web Attack ï¿½ Brute Force",
    3: "Web Attack ï¿½ XSS",
    4: "Web Attack ï¿½ Sql Injection",
    5: "DoS slowloris",
    6: "DoS Slowhttptest",
    7: "DoS Hulk",
    8: "DoS GoldenEye",
    9: "Heartbleed",
    10: "FTP-Patator",
    11: "SSH-Patator",
    12: "Portscan",
    13: "Infiltration",
    14: "Bot"
    # Add more attack types based on your model's output classes
}


def preprocess_data(features):
    """
    Load and preprocess features for prediction, using the saved scaler.
    """
    try:
        # Load the feature data
        df = pd.DataFrame(features)
        # Replace any `inf` or `-inf` values with 0
        df.replace([np.inf, -np.inf], 0, inplace=True)

        # Handle missing values
        if df.isnull().values.any():
            df.fillna(0, inplace=True)

        # Load the saved scaler
        scaler = joblib.load("models/scaler.joblib")

        # Transform the features using the loaded scaler
        features_transformed = scaler.transform(df)
        return features_transformed
    except Exception as e:
        print("Error loading or preprocessing data:")
        print(str(e))
        return None

# Define the packet limit (e.g., 1000 packets)
PACKET_LIMIT = 20000


def get_packets_from_pcap(pcap_path):
    """
    Read all packets from the specified .pcap file.
    """
    try:
        packets = []
        if not os.path.isfile(pcap_path):
            return packets  # File doesn't exist, so return an empty list

        for packet in RawPcapReader(pcap_path):
            packets.append(packet[0])  # Append the raw packet
        return packets
    except Exception as e:
        print(f"Error reading packets from .pcap file {pcap_path}: {e}")
        return []


def write_buffer_to_pcap(buffer, pcap_path="temp_live_capture.pcap"):
    """
    Write the buffered packets to a temporary .pcap file. If the total packet count
    exceeds the defined limit, clear older packets and overwrite with newer packets.
    """
    try:
        # Step 1: Read existing packets from the file
        existing_packets = get_packets_from_pcap(pcap_path)

        # Step 2: Combine old and new packets, and trim to fit within the limit
        combined_packets = existing_packets + buffer
        if len(combined_packets) > PACKET_LIMIT:
            # Keep the newest packets within the limit
            combined_packets = combined_packets[-PACKET_LIMIT:]

        # Step 3: Rewrite the file with the updated packet list
        wrpcap(pcap_path, combined_packets)

        print(f"Wrote {len(combined_packets)} packets to {pcap_path} (including {len(buffer)} new packets)")
        return pcap_path
    except Exception as e:
        print(f"Error writing packets to .pcap file: {e}")
        return None



def process_packet(packet):
    """
    Callback function for sniffing live packets.
    Buffers packets and processes them when the buffer reaches the batch size.
    """
    global packet_buffer, processed_packets

    try:
        # Add the packet to the buffer
        packet_buffer.append(packet)

        # Check if the buffer has reached the batch size
        if len(packet_buffer) >= BATCH_SIZE:
            # Write the buffered packets to a temporary .pcap file
            temp_pcap_path = write_buffer_to_pcap(packet_buffer)

            # Clear the packet buffer
            packet_buffer = []
            if temp_pcap_path:
                # Extract features from the .pcap file
                extracted_features = pd.DataFrame(extract_pcap_features(temp_pcap_path))

                # Verify and preprocess the extracted features
                if extracted_features is not None and len(extracted_features) > 0:
                    # Create a separate DataFrame for preprocessing and models, excluding unnecessary columns
                    model_data = extracted_features.drop(['src_ip', 'dst_ip', 'protocol'], axis=1, errors='ignore')

                    # Preprocess the data
                    processed_data = preprocess_data(model_data)

                    # Get predictions from the models
                    rf_predictions = list(map(int, rf_model.predict(processed_data)))
                    nn_probabilities = nn_model.predict(processed_data)
                    nn_predictions = list(map(int, np.argmax(nn_probabilities, axis=1)))

                    # Combine the features with predictions and format for the frontend
                    for i in range(len(extracted_features)):
                        # Determine final prediction
                        final_pred = nn_predictions[i] if rf_predictions[i] != nn_predictions[i] else rf_predictions[i]
                        attack_type = ATTACK_TYPES.get(final_pred, "Unknown")

                        # Extract relevant packet information (including src_ip and dest_ip for printing/display)
                        src_ip = extracted_features.iloc[i].get('src_ip', 'Unknown')
                        dst_ip = extracted_features.iloc[i].get('dst_ip', 'Unknown')
                        destination_port = extracted_features.iloc[i].get('Destination Port', 'Unknown')
                        protocol = extracted_features.iloc[i].get('protocol', 'Unknown')
                        flow_duration = extracted_features.iloc[i].get('Flow Duration', 0)

                        # Create a packet entry
                        packet_entry = {
                            "flow_duration": float(flow_duration),
                            "source": src_ip,
                            "destination": dst_ip,
                            "destination_port": int(destination_port),
                            "protocol": protocol,
                            "prediction": attack_type,
                            "features": extracted_features.iloc[i].to_dict()
                            # Include all original features for display
                        }

                        # Add to processed packets
                        processed_packets.append(packet_entry)

                        # Keep only the latest 100 packets to prevent memory issues
                        '''if len(processed_packets) > 100:
                            processed_packets = processed_packets[-100:]'''

                    print(f"Processed {len(extracted_features)} packets. Total in memory: {len(processed_packets)}")
                else:
                    print("No valid features were extracted from the captured packets.")
            else:
                print("Temporary .pcap file could not be created for feature extraction.")

    except Exception as e:
        print(f"Error processing packet: {e}")



def start_sniffing(interface):
    """
    Starts live packet sniffing on the specified network interface.
    """
    global capturing
    capturing = True
    print(f"Started sniffing on interface: {interface}")
    sniff(iface=interface, prn=process_packet, stop_filter=lambda x: not capturing)


def stop_sniffing():
    """
    Stops the live packet sniffing process.
    """
    global capturing
    capturing = False
    print("Stopped sniffing.")


@app.route('/')
def index():
    """
    Render the homepage.
    """
    return render_template('index.html')


@app.route('/networks', methods=['GET'])
def list_networks():
    """
    Get available network interfaces.
    """
    interfaces = get_if_list()
    return jsonify(interfaces)


@app.route('/start_capture', methods=['POST'])
def start_capture():
    """
    Start capturing packets on the selected network interface.
    """
    global processed_packets
    processed_packets = []  # Reset previous capture data
    interface = request.json.get("interface")  # Selected network interface

    # Start sniffing in a separate thread
    threading.Thread(target=start_sniffing, args=(interface,), daemon=True).start()
    return jsonify({"status": f"Started capturing on {interface}."})


@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    """
    Stop capturing packets.
    """
    stop_sniffing()
    return jsonify({"status": "Stopped capturing packets."})


@app.route('/get_packets', methods=['GET'])
def get_packets():
    """
    Return processed packets for the frontend to display.
    This endpoint will be polled by the frontend.
    """
    global processed_packets
    try:
        # If there are no processed packets yet, return an empty array
        if not processed_packets:
            return jsonify({"packets": []})

        # Return the most recent packets first (up to 20)
        recent_packets = processed_packets[-20:]
        # Return in reverse order so newest are at the top
        return jsonify({
            "packets": recent_packets
        })
    except Exception as e:
        print(f"Error retrieving packet data: {e}")
        return jsonify({
            "error": str(e),
            "message": "An error occurred while fetching packet data."
        }), 500


@app.route('/analyze_pcap', methods=['POST'])
def analyze_pcap():
    """
    Analyze a PCAP file for network traffic and predict attack types.
    """
    try:
        # Check if a file was uploaded
        if 'pcap_file' not in request.files:
            return jsonify({"error": "No file uploaded. Please upload a .pcap file."}), 400

        pcap_file = request.files['pcap_file']

        # Save uploaded file to a temporary location
        temp_path = os.path.join("temp", pcap_file.filename)
        os.makedirs("temp", exist_ok=True)
        pcap_file.save(temp_path)

        # Extract features using the function from extract_features
        extracted_features = pd.DataFrame(extract_pcap_features(temp_path))

        if extracted_features is None or extracted_features.empty:
            return jsonify({"error": "No valid features extracted from the PCAP file."}), 500

        # Preprocess the features (excluding unnecessary columns)
        model_data = extracted_features.drop(['src_ip', 'dst_ip', 'protocol'], axis=1, errors='ignore')
        processed_data = preprocess_data(model_data)

        if processed_data is None:
            return jsonify({"error": "Error encountered during preprocessing."}), 500

        # Perform predictions using the models
        rf_predictions = list(map(int, rf_model.predict(processed_data)))
        nn_probabilities = nn_model.predict(processed_data)
        nn_predictions = list(map(int, np.argmax(nn_probabilities, axis=1)))

        # Combine predictions and prepare the response
        predictions = []
        for i in range(len(extracted_features)):
            # Determine final prediction
            final_pred = nn_predictions[i] if rf_predictions[i] != nn_predictions[i] else rf_predictions[i]
            attack_type = ATTACK_TYPES.get(final_pred, "Unknown")

            # Include relevant details for each prediction
            predictions.append({
                "flow_duration": float(extracted_features.iloc[i].get('Flow Duration', 0)),
                "source": extracted_features.iloc[i].get('src_ip', 'Unknown'),
                "destination": extracted_features.iloc[i].get('dst_ip', 'Unknown'),
                "destination_port": int(extracted_features.iloc[i].get('Destination Port', 0)),
                "protocol": extracted_features.iloc[i].get('protocol', 'Unknown'),
                "prediction": attack_type,
                "features": extracted_features.iloc[i].to_dict()  # Include original features
            })

        # Return predictions as JSON
        return jsonify({"predictions": predictions})
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")
        return jsonify({"error": str(e), "message": "An error occurred during PCAP analysis."}), 500

if __name__ == "__main__":
    # Fix: Set child watcher for subprocess support
    if asyncio.get_event_loop().is_running():
        raise RuntimeError("This script must be executed in a standalone Python process.")

    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    asyncio.get_child_watcher().attach_loop(asyncio.new_event_loop())

    app.run(host='0.0.0.0', port=8080, debug=True)
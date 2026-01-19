TEST_MODE = False   # set to False after testing

from scapy.all import sniff, IP
from collections import defaultdict
import time
import statistics

packet_count = defaultdict(int)
history = []

WINDOW = 10  # seconds
start_time = time.time()

def packet_handler(packet):
    global start_time

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_count[src_ip] += 1

    current_time = time.time()

    if TEST_MODE:
    # simulate high traffic from a test IP
     packet_count["192.168.1.100"] += 120


    if current_time - start_time >= WINDOW:
        print("\n--- Adaptive Traffic Analysis ---")

        total_packets = sum(packet_count.values())
        history.append(total_packets)

        # Calculate adaptive threshold
        if len(history) > 1:
            avg = statistics.mean(history)
            threshold = avg * 1.5
        else:
            threshold = 50  # initial safe value

        print(f"Adaptive Threshold: {int(threshold)} packets")

        for ip, count in packet_count.items():
            print(f"{ip} -> {count} packets")

            if count > threshold:
    excess = count - threshold

    if count <= threshold * 1.2:
        severity = "LOW"
    elif count <= threshold * 1.5:
        severity = "MEDIUM"
    else:
        severity = "HIGH"

    print(
        f"⚠️ ALERT: Abnormal traffic detected\n"
        f"   Severity        : {severity}\n"
        f"   Source IP       : {ip}\n"
        f"   Packet Count    : {count}\n"
        f"   Adaptive Limit  : {int(threshold)}\n"
        f"   Excess Packets  : {int(excess)}\n"
        f"   Reason          : Packet rate exceeded adaptive threshold\n"
    )


        print("---------------------------------\n")

        packet_count.clear()
        start_time = current_time


print("Starting adaptive real-time intrusion detection...")
sniff(filter="ip", prn=packet_handler, store=False)


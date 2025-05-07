import subprocess
import json
import time
from collections import defaultdict, deque

THRESHOLD = 2
WINDOW_SECONDS = 3
ip_syn_times = defaultdict(deque)

def capture_batch():
    cmd = [
        "sudo", "tshark",
        "-i", "en0",
        "-f", "tcp[tcpflags] & tcp-syn != 0",
        "-c", "5",         # Capture 5 packets at a time
        "-T", "json"
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

while True:
    packets = capture_batch()
    current_time = time.time()

    for packet in packets:
        layers = packet.get('_source', {}).get('layers', {})
        ip_layer = layers.get('ip', {})
        src_ip = ip_layer.get('ip.src')
        print(f"Packet from: {src_ip}")

        if not src_ip:
            continue

        syn_times = ip_syn_times[src_ip]
        syn_times.append(current_time)

        # Remove old timestamps
        while syn_times and current_time - syn_times[0] > WINDOW_SECONDS:
            syn_times.popleft()

        if len(syn_times) > THRESHOLD:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: SYN flood suspected from {src_ip} ({len(syn_times)} SYNs in {WINDOW_SECONDS}s)")


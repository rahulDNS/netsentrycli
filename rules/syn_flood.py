import subprocess
import json
import time
from collections import defaultdict, deque
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# InfluxDB Configuration
INFLUX_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUX_TOKEN = "gN7dcTC-8vGDnX-hAwvVQLZf-QxmKpCSRwN0qOAH-V7aqbL60lF6su9LwcERVWMGfyW6UzdHBYjrj3GQx--Hdg=="
INFLUX_ORG = "Data Analyst"
INFLUX_BUCKET = "_monitoring"

# Detection settings
THRESHOLD = 2
WINDOW_SECONDS = 4
ip_syn_times = defaultdict(deque)

# InfluxDB client setup
client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = client.write_api(write_options=SYNCHRONOUS)

def capture_batch():
    cmd = [
        "sudo", "tshark",
        "-i", "en0",
        "-f", "tcp[tcpflags] & tcp-syn != 0",
        "-c", "5",
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

        while syn_times and current_time - syn_times[0] > WINDOW_SECONDS:
            syn_times.popleft()

        if len(syn_times) > THRESHOLD:
            alert_msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: SYN flood suspected from {src_ip} ({len(syn_times)} SYNs in {WINDOW_SECONDS}s)"
            print(alert_msg)

            # Write alert to InfluxDB
            point = (
                Point("syn_alerts")
                .tag("source_ip", src_ip)
                .field("syn_count", len(syn_times))
                .field("window", WINDOW_SECONDS)
                .time(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
            )
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)

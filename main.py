import subprocess

print("[INFO] Starting NetSentryCLI")
print("[INFO] Running SYN Flood detection rule...")

try:
    subprocess.run(["python3", "rules/syn_flood.py"])
except KeyboardInterrupt:
    print("\n[INFO] Stopped by user. Exiting NetSentryCLI.")

# NetSentryCLI 🔐📡

A lightweight, terminal-based intrusion detection tool built using `tshark` and Python.  
Currently features real-time SYN flood detection using packet analysis.

---

## 🚀 Features

- Live network packet monitoring via `tshark`
- SYN flood detection using sliding window thresholding
- Modular rule-based design (start with `syn_flood.py`)
- Simple CLI interface (`main.py`)
- Easily extendable with more detection rules (e.g., DNS, ICMP)

---

## 🛠️ Requirements

- Python 3.x
- Wireshark (`tshark`)
- macOS/Linux terminal (root/sudo access required)

Install dependencies:
```bash
brew install wireshark   # for macOS
sudo apt install tshark  # for Linux

STRUCTURE:

netsentrycli/
│
├── main.py                 # CLI launcher
├── .gitignore              # Exclude logs, caches
│
├── rules/                  # Detection rule modules
│   └── syn_flood.py        # SYN flood detection logic
│
└── logs/                   # (Optional) Alert logs


Run it by: python3 main.py

To simulate a SYN flood (optional testing):
for i in {1..10}; do sudo nmap -sS -p 1-1000 127.0.0.1; done



How It Works

Captures batches of SYN packets using tshark

Tracks SYN counts per source IP in a 5-second window

Raises an alert if SYNs exceed the defined threshold



🧩 Coming Soon
DNS tunneling detection

Alert logging system

Multi-rule support (threaded)

CLI dashboard





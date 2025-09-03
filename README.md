# 🛠️ Python Port Scanner

This is a Python-based **port scanner** that can scan a target IP address for open, closed, or filtered ports using **SYN**, **TCP**, or **UDP** protocols.  
It also includes an **optional OS detection** feature.

The tool uses **multithreading** for faster scans and relies on libraries like `scapy`, `socket`, and `colorama`.

---

## 📦 Features

- Scan a target IP address with:
  - SYN scan
  - TCP connect scan
  - UDP scan
- Detect open, closed, and filtered ports
- Optional OS detection
- Threaded scanning (fast and efficient)
- Shows total scan time

---

## 🧰 Dependencies

Make sure you have **Python 3.6+** and the following libraries:

- `scapy`
- `socket` (standard library)
- `queue` (standard library)
- `colorama`
- `concurrent.futures` (standard library)
- `datetime` (standard library)

---

### 📥 Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/port-scanner.git
cd PORTHAWKSCANNER

Install required Python packages:
pip install -r requirements.txt

Usage:
python3 scanner.py -t <target_ip> -p <ports> [options]

Scan Modes (choose one):
| Option        | Description              |
| ------------- | ------------------------ |
| `-S`, `--syn` | Perform SYN scan         |
| `-T`, `--tcp` | Perform TCP connect scan |
| `-U`, `--udp` | Perform UDP scan         |

Optional:
| Option                | Description                        |
| --------------------- | ---------------------------------- |
| `-o`, `--osdetection` | Try to detect the operating system |

Examples:
# SYN scan on port 80
python3 scanner.py -t 192.168.1.1 -p 80 -S

# TCP scan on multiple ports
python3 scanner.py -t 10.0.0.5 -p 22,80,443 -T

# UDP scan with OS detection
python3 scanner.py -t 192.168.0.10 -p 53 -U -o

# SYN scan on a range of ports
python3 scanner.py -t 192.168.1.100 -p 20-100 -S

⚠️ Administrator Rights

Some scans (like SYN or OS detection) may require administrator/root privileges.

Linux/macOS:
sudo python3 scanner.py ...

📁 Project Structure:
PORTHAWKSCANNER/
├── scanner.py             # Main script
├── scan_syn.py            # SYN scan logic
├── scan_tcp.py            # TCP scan logic
├── scan_udp.py            # UDP scan logic
├── os_detection.py        # OS detection feature
├── scan_core.py           # Core scanning logic
├── utils.py               # IP checking and reachability
├── queues.py              # Port status handling (open, closed, filtered)
├── requirements.txt       # Python dependencies
└── README.md              # This file

Port Status Definitions:
Open: The port responded and is accepting connections.
Closed: The port responded but refused the connection.
Filtered: No response. A firewall may be blocking the port.

📄 License
This project is open-source and free to use for learning and personal projects.
You can add a license if needed (MIT, GPL, etc.).

👨‍💻 Author:
Developed by sokkeita

🧠 Tips
Always scan responsibly.
Do not scan devices or networks without permission — it's illegal and unethical.
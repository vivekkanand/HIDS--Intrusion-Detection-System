HIDS- Intrusion Detection System

Run:
python -m venv .venv
# activate venv
pip install -r requirements.txt

python run.py --config config.yaml

Notes:
- Run as admin/root to capture packets with scapy.
- Windows: install Npcap and ensure pywin32 for Event Log access.

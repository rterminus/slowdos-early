import re
import subprocess
import sys
from pathlib import Path

import config


def extract_pcap(pcap_path: Path, output_csv: Path):
    """Runs TShark to extract PCAP fields and output to CSV"""

    command = [
        "tshark", 
        "-r", str(pcap_path),
        "-Y", "tcp",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "tcp.stream",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.ttl",
        "-e", "ip.id",
        "-e", "ip.checksum",
        "-e", "tcp.flags",
        "-e", "tcp.len",
        "-e", "frame.len",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.checksum",
        "-e", "tcp.window_size_value",
        "-e", "tcp.seq_raw",
        "-e", "tcp.ack_raw"
    ]

    with open(output_csv, "w") as f:
        subprocess.run(command, stdout=f, check=True)


def main():
    valid_pattern = re.compile(r"^(taxa\d+|intervalo\d+|benigno_only)_rep\d+$")

    pcap_dir = config.RAW_DIR / "pcaps"

    print(f"searching .pcap files in {config.RAW_DIR}...")

    for pcap_path in pcap_dir.glob("*.pcap"):
        if not valid_pattern.match(pcap_path.stem):
            print(f"ignoring non-pattern file: {pcap_path.name}")
            continue

        csv_name = f"{pcap_path.stem}_packets.csv"
        output_path = config.INTERIM_DIR / csv_name

        print(f"extracting {pcap_path.name} → {csv_name}")
        extract_pcap(pcap_path, output_path)


if __name__ == "__main__":
    main()

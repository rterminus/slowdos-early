import re
import sys

import pandas as pd

import config
from features.assemble import merge_features_labels
from features.build_flows import flatten_flows, line_per_packet
from features.label import extract_labels


def parse_metadata(filename: str):
    """extracts run_id, pcap_type, series, value and rep from filename"""

    run_id = filename.replace("_packets", "")
    parts = run_id.split("_")
    rep_str = parts[-1].replace("rep", "")

    if run_id.startswith("benigno"):
        return run_id, "benign", "benign", 0, rep_str

    # matches pattern like 'taxa100' -> group(1)='taxa', group(2)='100'
    match = re.match(r"([a-zA-Z]+)(\d+)", parts[0])
    if match:
        series = match.group(1)
        value = int(match.group(2))
    else:
        series = parts[0]
        value = 0

    return run_id, "attack", series, value, rep_str


def run_pipeline(df: pd.DataFrame, filename: str) -> pd.DataFrame:
    df_raw = df.copy()

    df_features, stats = line_per_packet(df_raw, port=config.PORT, n_max=config.N_MAX)
    print(
        f"  -> DISCARDED: {stats['removed_duplicates']} cloned packets, {stats['flows_wo_syn']} flows without SYN"
    )
    df_flat = flatten_flows(df_features)

    df_labels = extract_labels(
        df_raw,
        port=config.PORT,
        attacker_ip=config.ATTACKER_IP,
        benign_ip=config.BENIGN_IP,
    )

    df_final = merge_features_labels(df_flat, df_labels)

    # extracting and injecting metadata
    run_id, flow_type, series, value, rep = parse_metadata(filename)

    df_final["run_id"] = run_id
    df_final["flow_type"] = flow_type
    df_final["series"] = series
    df_final["value"] = value
    df_final["rep"] = rep

    # preventing duplates across different PCAPs
    df_final["flow_id"] = run_id + "_" + df_final["flow_id"].astype(str)

    return df_final


if __name__ == "__main__":
    print("initializing feature extraction pipeline...")
    all_flows = []

    valid_pattern = re.compile(r"^(taxa\d+|intervalo\d+|benigno_only)_rep\d+$")

    for csv_path in config.INTERIM_DIR.glob("*_packets.csv"):
        run_id = csv_path.stem.replace("_packets", "")

        if not valid_pattern.match(run_id):
            print(f"\nerror: garbage file detected in data/interim: {csv_path.name}")
            print("clear the directory and run the extraction again")
            sys.exit(1)

        print(f"processing: {csv_path.name}")
        df_raw = pd.read_csv(csv_path)

        df_processed = run_pipeline(df_raw, filename=csv_path.stem)
        all_flows.append(df_processed)

    df_consolidated = pd.concat(all_flows, ignore_index=True)

    output_path = config.PROCESSED_DIR / "flows_n8_v1.csv"
    df_consolidated.to_csv(output_path, index=False)

    print(f"success! {len(df_consolidated)} flows saved to {output_path}.")

import pandas as pd

import config
from features.assemble import merge_features_labels
from features.build_flows import flatten_flows, line_per_packet
from features.label import extract_labels


def run_pipeline(df: pd.DataFrame):
    df_raw = df.copy()

    df_features = line_per_packet(df_raw, port=config.PORT, n_max=config.N_MAX)
    df_flat = flatten_flows(df_features)

    df_labels = extract_labels(df_raw, port=config.PORT, attacker_ip=config.ATTACKER_IP)

    df_final = merge_features_labels(df_flat, df_labels)
    df_final.to_csv("data/processed/flows_n8_v1.csv", index=False)


if __name__ == "__main__":
    df_raw = pd.read_csv("data/interim/taxa100_rep1_packets.csv")

    print("initializing feature extraction pipeline...")
    run_pipeline(df_raw)
    print("success! flows_n8_v1 generated in data/processed/")

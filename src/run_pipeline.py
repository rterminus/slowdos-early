import pandas as pd

from features.assemble import merge_features_labels
from features.build_flows import flatten_flows, line_per_packet
from features.label import extract_labels

port = 80


def run_pipeline(df: pd.DataFrame):
    df_raw = df.copy()

    df_features = line_per_packet(df_raw, port=port)
    df_flat = flatten_flows(df_features)

    df_labels = extract_labels(df_raw, port=port)

    df_final = merge_features_labels(df_flat, df_labels)
    df_final.to_csv("data/processed/flows_n8_v1.csv", index=False)


if __name__ == "__main__":
    df_raw = pd.read_csv("data/interim/taxa100_rep1_packets.csv")

    print("Initializing feature extraction pipeline...")
    run_pipeline(df_raw)
    print("Success! flows_n8_v1 generated in data/processed/")

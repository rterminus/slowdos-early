import numpy as np
import pandas as pd


def extract_labels(
    df: pd.DataFrame, port: int, attacker_ip: str, benign_ip: str
) -> pd.DataFrame:
    df_raw = df.copy()

    df_raw = df.groupby("tcp.stream").first().reset_index()

    # identifying conection origin
    df_raw["is_client_src"] = df_raw["tcp.srcport"] != port
    df_raw["client_ip"] = np.where(
        df_raw["is_client_src"], df_raw["ip.src"], df_raw["ip.dst"]
    )

    # strict validation
    df_raw["label"] = np.where(
        df_raw["client_ip"] == attacker_ip, 1,
        np.where(df_raw["client_ip"] == benign_ip, 0, np.nan),
    )

    if df_raw["label"].isna().any():
        raise ValueError("unknown IPs detected in capture. verify the environment.")

    df_raw = df_raw.rename(columns={"tcp.stream": "flow_id"})
    return df_raw[["flow_id", "label"]]

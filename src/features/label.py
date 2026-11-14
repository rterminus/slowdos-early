import numpy as np
import pandas as pd


def extract_labels(df: pd.DataFrame, port: int, attacker_ip: str) -> pd.DataFrame:
    df_raw = df.copy()

    # isolating forward packets
    df_raw = df_raw[df_raw["tcp.dstport"] == port]

    # extracting client IP by flow
    ips = df_raw.groupby("tcp.stream")["ip.src"].first()

    # transforming IP into label
    labels = np.where(ips == attacker_ip, 1, 0)

    # formatting the output dataframe
    df_labels = pd.DataFrame({"tcp.stream": ips.index, "label": labels})

    return df_labels

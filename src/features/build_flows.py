import numpy as np
import pandas as pd


def line_per_packet(df: pd.DataFrame, port: int, n_max: int):
    # copying df for modifying and sorting by stream + timestamp
    df_feat = df.copy()
    df_feat = df_feat.sort_values(by=["tcp.stream", "frame.time_epoch"])

    # creating flow i column
    df_feat["i"] = df_feat.groupby("tcp.stream").cumcount()
    df_feat = df_feat[df_feat["i"] < n_max]

    # checking direction: 1 if client->server, otherwise -1
    df_feat["b_dir"] = np.where(df_feat["tcp.srcport"] == port, -1, 1)

    # diff between current and previous row timestamp for iat
    df_feat["b_iat"] = (
        df_feat.groupby("tcp.stream")["frame.time_epoch"].diff().fillna(0)
    )

    # calculates total time since flow start
    df_feat["b_t"] = df_feat["frame.time_epoch"] - df_feat.groupby("tcp.stream")[
        "frame.time_epoch"
    ].transform("min")

    # renaming columns
    df_feat = df_feat.rename(
        columns={
            "tcp.len": "b_plen",
            "tcp.flags": "f_flags",
            "tcp.window_size_value": "f_win",
            "ip.ttl": "h_ttl",
            "ip.id": "h_ipid",
            "ip.checksum": "h_ipcsum",
            "tcp.checksum": "h_tcpcsum",
            "tcp.seq_raw": "h_seq",
            "tcp.ack_raw": "h_ack",
        }
    )

    # exporting final columns: features and metadata
    final_columns = [
        "tcp.stream",
        "frame.time_epoch",
        "i",
        "b_dir",
        "b_plen",
        "b_iat",
        "b_t",
        "f_flags",
        "f_win",
        "h_ttl",
        "h_ipid",
        "h_ipcsum",
        "h_tcpcsum",
        "h_seq",
        "h_ack",
    ]

    return df_feat[final_columns]


def flatten_flows(df: pd.DataFrame):
    df_meta = (
        df.groupby("tcp.stream")
        .agg(t_start=("frame.time_epoch", "min"), n_pkts=("tcp.stream", "count"))
        .reset_index()
    )

    df = df.drop(columns=["frame.time_epoch"])

    df_flat = df.pivot(index="tcp.stream", columns="i")
    df_flat.columns = [f"{feat}_{pos + 1}" for feat, pos in df_flat.columns]
    df_flat = df_flat.reset_index()

    df_final = pd.merge(df_meta, df_flat, on="tcp.stream")
    df_final = df_final.rename(columns={"tcp.stream": "flow_id"})

    return df_final

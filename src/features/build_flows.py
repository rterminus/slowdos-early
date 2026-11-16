import numpy as np
import pandas as pd


def line_per_packet(df: pd.DataFrame, port: int, n_max: int):
    # copying df for modifying and sorting by stream + timestamp
    df_feat = df.copy()
    stats = {"raw": len(df_feat), "initial_flows": df_feat["tcp.stream"].nunique()}
    df_feat = df_feat.sort_values(by=["tcp.stream", "frame.time_epoch"])

    # structurally equal packets identifiers
    dup_key = [
        "ip.id",
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.seq_raw",
        "tcp.ack_raw",
        "tcp.len",
        "tcp.flags",
    ]

    # checks time diff for capture copy
    df_feat["dt_dup"] = df_feat.groupby(dup_key)["frame.time_epoch"].diff()
    is_capture_copy = df_feat["dt_dup"] < 0.001

    stats["removed_duplicates"] = is_capture_copy.sum()
    df_feat = df_feat[~is_capture_copy].drop(columns="dt_dup")

    # SYN filter
    first_packets = df_feat.groupby("tcp.stream")["tcp.flags"].first()

    def is_syn(flag_val):
        try:
            return (int(str(flag_val), 16) & 0x02) != 0
        except:
            return False

    valid_flows = first_packets[first_packets.apply(is_syn)].index.to_list()
    stats["flows_wo_syn"] = stats["initial_flows"] - len(valid_flows)
    df_feat = df_feat[df_feat["tcp.stream"].isin(valid_flows)]

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

    # converting hex to dec
    hex_cols = ["f_flags", "h_ipid", "h_ipcsum", "h_tcpcsum"]
    for col in hex_cols:
        df_feat[col] = df_feat[col].apply(
            lambda x: int(str(x), 16) if pd.notna(x) and isinstance(x, str) else x
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

    return df_feat[final_columns], stats


def flatten_flows(df: pd.DataFrame):
    t_min = df["frame.time_epoch"].min()
    df_meta = (
        df.groupby("tcp.stream")
        .agg(
            t_start=("frame.time_epoch", lambda x: x.min() - t_min),
            n_pkts=("tcp.stream", "count"),
        )
        .reset_index()
    )

    df = df.drop(columns=["frame.time_epoch"])

    df_flat = df.pivot(index="tcp.stream", columns="i")
    df_flat.columns = [f"{feat}_{pos + 1}" for feat, pos in df_flat.columns]
    df_flat = df_flat.reset_index()

    df_final = pd.merge(df_meta, df_flat, on="tcp.stream")
    df_final = df_final.rename(columns={"tcp.stream": "flow_id"})

    for col in df_final.columns:
        if df_final[col].dtype == "float64" and col.startswith(
            (
                "b_dir",
                "b_plen",
                "f_flags",
                "f_win",
                "h_ttl",
                "h_ipid",
                "h_ipcsum",
                "h_tcpcsum",
                "h_seq",
                "h_ack",
            )
        ):
            df_final[col] = df_final[col].astype("Int64")

    return df_final

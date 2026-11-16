import pandas as pd

import config


def check_data_leakage(df: pd.DataFrame):
    df_check = df.copy()

    allowed_prefixes = (
        "b_",
        "f_",
        "h_",
        "t_",
        "n_",
        "flow_id",
        "run_id",
        "label",
        "flow_type",
        "series",
        "value",
        "rep",
    )
    for column in df.columns:
        assert column.startswith(allowed_prefixes), f"data leakage detected: {column}"


def check_labels(df: pd.DataFrame):
    df_check = df.copy()

    n_labels = len(df["label"].unique())
    assert n_labels == 2, f"label different than 2: {n_labels}"


def check_nans(df: pd.DataFrame):
    df_check = df.copy()

    total_nans = df.isna().sum().sum()
    print(f"total of NaNs on dataset: {total_nans}")

    nan_per_column = df.isna().sum()
    columns_with_nan = nan_per_column[nan_per_column > 0]

    if not columns_with_nan.empty:
        print(f"\ncolumns containing NaNs:\n{columns_with_nan.to_string()}")

    print()


def check_invariants(df: pd.DataFrame):
    df_check = df.copy()

    # no IP leakage or absolute timestamps
    assert not any(
        col.startswith(("ip.", "frame.time_epoch")) for col in df_check.columns
    ), "feature leakage detected."

    # the first packet from all flows must be client's SYN -> dir 1
    assert (
        df_check["b_dir_1"] == 1
    ).all(), "there are flows where the first packet didn't come from client"
    assert (df_check["b_iat_1"] == 0).all(), "first packet's IAT must be strictly 0."
    assert (
        df_check["b_t_1"] == 0
    ).all(), "first packet's timestamp must be strictly 0."
    assert (
        df_check["f_flags_1"] == 2
    ).all(), "there are flows where the first packet isn't a pure SYN."

    # counting ranges
    assert df["n_pkts"].between(1, 8).all(), "there are flows with n_pkts out of range."
    assert df["flow_id"].is_unique, "there are flow_id collisions in the final dataset."

    # label and metadada consistence
    benigns = df[df["flow_type"] == "benign"]
    assert (
        benigns["label"] == 0
    ).all(), "flows marked as benign_only have attack's label=1"


if __name__ == "__main__":
    file_final = config.PROCESSED_DIR / "flows_n8_v1.csv"
    print(f"starting QA: {file_final.name}\n")

    df_final = pd.read_csv(file_final)

    check_data_leakage(df_final)
    check_labels(df_final)
    check_nans(df_final)
    check_invariants(df_final)

    print("QA successfully finished")

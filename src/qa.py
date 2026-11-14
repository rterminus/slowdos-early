import pandas as pd

import config


def check_data_leakage(df: pd.DataFrame):
    df_check = df.copy()

    allowed_prefixes = ("b_", "f_", "h_", "tcp.stream", "label")
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


if __name__ == "__main__":
    file_final = config.PROCESSED_DIR / "flows_n8_v1.csv"
    print(f"starting QA: {file_final.name}\n")

    df_final = pd.read_csv(file_final)

    check_data_leakage(df_final)
    check_labels(df_final)
    check_nans(df_final)

    print("QA successfully finished")

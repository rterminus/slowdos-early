import pandas as pd


def merge_features_labels(
    df_flat: pd.DataFrame, df_labels: pd.DataFrame
) -> pd.DataFrame:
    df_final = pd.merge(df_flat, df_labels, on="tcp.stream", how="inner")

    return df_final

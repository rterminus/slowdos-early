import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from src.features.build_flows import flatten_flows, line_per_packet


def test_line_per_packet_stream_300():
    # loading fixtures
    df_packets = pd.read_csv("tests/fixtures/packets_attack_300.csv")
    df_expected = pd.read_csv("tests/fixtures/expected_attack_300.csv")

    # target function
    df_result = line_per_packet(df_packets, port=80)

    # remove identifiers to match the 6-column fixture
    df_result_features = df_result.drop(columns=["tcp.stream", "i"])

    # compares dataframes
    assert_frame_equal(df_result_features, df_expected, check_dtype=False, atol=2e-6)


def test_flatten_flows():
    # mockup dataframe with 2 short flows (i: 0 and 1)
    df_fake = pd.DataFrame(
        {
            "tcp.stream": [0, 0, 1, 1],
            "i": [0, 1, 0, 1],
            "b_dir": [1, -1, 1, 1],
            "b_plen": [0, 151, 0, 0],
        }
    )

    df_flat = flatten_flows(df_fake)

    # verifies column renaming correctness
    colunas_esperadas = ["tcp.stream", "b_dir_1", "b_dir_2", "b_plen_1", "b_plen_2"]

    assert list(df_flat.columns) == colunas_esperadas
    # should return one line per flow and 5 columns
    assert df_flat.shape == (2, 5)

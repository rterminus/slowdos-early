import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from src.features.build_flows import flatten_flows, line_per_packet


def test_line_per_packet_stream_300():
    # loading fixtures
    df_packets = pd.read_csv("tests/fixtures/packets_attack_300.csv")
    df_expected = pd.read_csv("tests/fixtures/expected_attack_300.csv")

    # IPv4 data mock
    df_packets["ip.ttl"] = 64
    df_packets["ip.id"] = "0x1234"
    df_packets["ip.checksum"] = "0xabcd"
    df_packets["tcp.checksum"] = "0x9876"
    df_packets["tcp.seq_raw"] = 1000
    df_packets["tcp.ack_raw"] = 0

    # target function
    df_result = line_per_packet(df_packets, port=80, n_max=8)

    # remove identifiers to match the 6-column fixture
    cols_to_drop = [
        "tcp.stream",
        "i",
        "frame.time_epoch",
        "h_ttl",
        "h_ipid",
        "h_ipcsum",
        "h_tcpcsum",
        "h_seq",
        "h_ack",
    ]
    df_result_features = df_result.drop(columns=cols_to_drop).reset_index(drop=True)

    # compares dataframes
    assert_frame_equal(df_result_features, df_expected, check_dtype=False, atol=2e-6)


def test_flatten_flows():
    # mockup dataframe with 2 short flows (i: 0 and 1)
    df_fake = pd.DataFrame(
        {
            "tcp.stream": [0, 0, 1, 1],
            "i": [0, 1, 0, 1],
            "frame.time_epoch": [1.0, 2.0, 3.0, 4.0],
            "b_dir": [1, -1, 1, 1],
            "b_plen": [0, 151, 0, 0],
        }
    )

    df_flat = flatten_flows(df_fake)

    # verifies column renaming correctness
    expected_columns = [
        "flow_id",
        "t_start",
        "n_pkts",
        "b_dir_1",
        "b_dir_2",
        "b_plen_1",
        "b_plen_2",
    ]

    assert list(df_flat.columns) == expected_columns
    # should return one line per flow and 7 columns
    assert df_flat.shape == (2, 7)

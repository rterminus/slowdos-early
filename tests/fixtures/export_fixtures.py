import pandas as pd

atk = pd.read_csv("data/interim/taxa50_rep1_packets.csv")
sub = atk[atk["tcp.stream"] == 300].sort_values("frame.time_epoch")
sub.to_csv("tests/fixtures/packets_attack_300.csv", index=False)
print(
        sub[
            [
                "tcp.srcport",
                "tcp.dstport",
                "tcp.flags",
                "tcp.len",
                "tcp.window_size_value",
                ]
            ].head(8)
        )
sub = sub.head(8)
print(sub["frame.time_epoch"].map(lambda x: f"{x:.9f}").to_string())

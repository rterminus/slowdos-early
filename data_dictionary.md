# Data Dictionary

## Scope and architecture

- **Base protocol**: exclusively IPv4 — restriction validated in Docker environment.
- **Flow definition**: bidirectional TCP connection, counting packets from both client and server, starting with a SYN observed (SYN=1, ACK=0), and grouped by the `tcp.stream` key. Flows without a valid initial SYN are discarded.
- **Observation window / early detection**: fixed to the first 8 packets of each connection (`N_MAX = 8`).

## Not features

IPs, ports (except for direction inference), absolute timestamps, `run_id`, `flow_type`, `series`, `value`, `rep`, `intervalo_s`, pcap names, and `tcp.stream` are metadata and **must never be used as predictive features**. They exist exclusively for dataset partitioning and traceability, preventing shortcut learning.

## Feature mapping

The pipeline flattens the first 8 packets into one row per flow. For each packet $i\in \{1, \dots, 8\}$, the features are positional (suffixed `_1` to `_8`) and are organized into three groups by prefix:

- `b_` — behavior (direction, payload size, IAT, elapsed time)
- `f_` — TCP flags and window (control-plane fields)
- `h_` — header artifacts (IPv4 and TCP header fields used as
  shortcut/artifact indicators, not behavior)

- `b_dir_i`: Direction (+1 for client→server, -1 for server→client), inferred from the server port defined in the testbed manifesto.
- `b_plen_i`: TCP payload size in bytes (0 for pure ACKs).
- `b_iat_i`: Inter-Arrival Time (seconds since the last packet in the same flow; fixed to 0 by convention in the 1st packet).
- `b_t_i`: Total time elapsed (seconds since the `frame.time_epoch` timestamp of the 1st flow packet).
- `h_ttl_i`: IPv4 Time-to-Live (TTL).
- `h_ipid_i`: IPv4 identification field.
- `h_seq_i`: TCP sequence number (raw).
- `h_ack_i`: TCP acknowledgment number (raw).
- `h_ipcsum_i`: IPv4 header checksum.
- `h_tcpcsum_i`: TCP checksum (includes the IPv4 pseudo-header with Source/Destination IPs, acting as a static identifier when hardware offload is enabled) — extracted, but removed from training features
- `f_flags_i`: Integer representation of TCP flags (Wireshark 12-bit format).
- `f_win_i`: Announced TCP window size (`tcp.window_size_value`), raw unscaled value.
- `f_retrans_i`: Binary value indicating packet retransmission (1 for retransmission, 0 for normal packet).

## Metadata and target

- `tcp.stream`: TShark index in the pcap.
- `run_id`: Execution identifier string derived from the filename (e.g., `taxa50_rep1`); serves as the base for data splitting.
- `flow_id`: Globally unique identifier formed by combining `run_id` and `tcp.stream`.
- `flow_type`: Traffic type or experimental condition parsed from the filename (`attack` or `benign`).
- `series`: The experimental variable being tested in the current run (e.g., `taxa`, `intervalo`, or `benigno_only`), parsed from the filename.
- `value`: The numerical value of the experimental variable (e.g., `50` for `taxa50`), parsed from the filename.
- `rep`: The repetition number of the experiment (e.g., `1` for `rep1`), parsed from the filename.
- `t_start`: Relative flow start timestamp (useful for debugging, not a feature).
- `n_pkts`: Number of packets observed (1 to 8) before connection termination or window limit.
- `no_response` (or `sem_resposta`): Binary flag (1 if no server→client packets exist in the window, indicating unresponded SYN retransmissions).
- `label`: Target variable (1 for attack/SlowHTTP [originating from IP .20], 0 for benign [originating from IP .30, even during attack windows]).

## Missing values

Inexistent positions in flows with less than 8 packets (i.e., when $i >$ `n_pkts`) are exported as `NaN`. `n_pkts` preserves the actual count.

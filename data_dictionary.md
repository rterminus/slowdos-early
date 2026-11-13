# Data Dictionary (v0)

## Scope and architecture

- **Base protocol**: exclusively IPv4 — restriction validated in Docker environment
- **Flow definition**: bidirectional TCP conection, grouped by `tcp.stream` key.
- **Observation window / early detection**: fixed in 8 first conection packets
  (`N_MAX = 8`)

## Feature mapping

The pipeline levels 8 lines of packets into 1 line per flow. For each packet
$i\in \{1, \dots, 8\}$:

- `b_dir_i`: Direction (+1 for client→server, -1 for server→client).
- `b_plen_i`: TCP payload size in bytes (0 for pure ACKs).
- `b_iat_i`: Inter-Arrival Time (seconds since the last packet in the same flow;
  0 in 1st packet).
- `b_t_i`: Total time elapsed (seconds since 1st flow packet).
- `h_ttl_i`: IPv4 Time-to-Live (TTL).
- `h_ipid_i`: IPv4 identification field.
- `h_seq_i`: TCP sequence number (raw).
- `h_ack_i`: TCP acknowledgment number (raw).
- `h_ipcsum_i`: IPv4 header checksum.
- `h_tcpcsum_i`: TCP checksum.
- `f_flags_i`: Integer representation of TCP flags.
- `f_win_i`: Announced TCP window size (`tcp.window_size_value`).

**River integration note:** Inexistent positions in flows with less than 8 packets
are exported as `NaN`.

## Metadata and target

- `tcp.stream`: Unique integer identifying the TCP connection — serves as primary
  key.
- `label`: Target variable (1 for attack/SlowHTTP, 0 for benign).

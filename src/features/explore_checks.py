import glob
import os

import pandas as pd

# colunas que, se idênticas, indicam o mesmo pacote visto duas vezes
CHAVE_DUP = [
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.len",
    "tcp.seq_raw",
    "tcp.ack_raw",
]


def col(df, nome):
    """Coluna do df, ou NaN se o tshark não a exportou nesse arquivo."""
    if nome in df.columns:
        return df[nome]
    return pd.Series(float("nan"), index=df.index)


def checar(caminho, porta=None):
    """porta=None: infere a porta do servidor pelos SYNs; ou passe um valor."""
    df = pd.read_csv(caminho)
    nome = os.path.basename(caminho).replace("_packets.csv", "")
    if df.empty:
        return {"pcap": nome, "pacotes": 0}

    # ip e hlim/ttl: usa ipv6 quando existe, senão ipv4
    df["src"] = col(df, "ipv6.src").fillna(col(df, "ip.src"))
    df["dst"] = col(df, "ipv6.dst").fillna(col(df, "ip.dst"))
    df["hl"] = col(df, "ipv6.hlim").fillna(col(df, "ip.ttl"))
    df["flags"] = df["tcp.flags"].apply(lambda x: int(x, 16))
    df = df.sort_values(["tcp.stream", "frame.time_epoch"])

    # syn puro = bit 0x02 ligado e bit 0x10 desligado
    df["syn"] = ((df["flags"] & 0x02) != 0) & ((df["flags"] & 0x10) == 0)

    # porta do servidor: destino mais comum entre os syn puros
    portas_syn = df.loc[df["syn"], "tcp.dstport"].value_counts()
    if porta is None:
        if portas_syn.empty:
            return {"pcap": nome, "pacotes": len(df), "erro": "nenhum syn puro"}
        porta = int(portas_syn.index[0])

    # portas: em cada pacote, exatamente um lado é a porta do servidor
    df["um_lado"] = (df["tcp.srcport"] == porta) ^ (df["tcp.dstport"] == porta)
    por_stream = df.groupby("tcp.stream")["um_lado"].all()

    tem_syn = df.groupby("tcp.stream")["syn"].any()
    primeiro_syn = df.groupby("tcp.stream")["syn"].first()

    n = df.groupby("tcp.stream").size()
    sem_syn = tem_syn.index[~tem_syn.to_numpy()]
    curtos_ok = n.index[((n < 8) & tem_syn).to_numpy()]

    # clientes: ips que enviam para a porta do servidor
    clientes = sorted(df.loc[df["tcp.dstport"] == porta, "src"].dropna().unique())

    # duplicatas: mesmo pacote visto duas vezes (captura em -i any)?
    # dt pequeno (microssegundos) = duplicata de captura; dt grande = retransmissão
    df["dup"] = df.duplicated(CHAVE_DUP, keep="first")
    primeiro_t = df.groupby(CHAVE_DUP)["frame.time_epoch"].transform("min")
    dt_dup = (df["frame.time_epoch"] - primeiro_t)[df["dup"]]
    dup_dt_med = dt_dup.median() if len(dt_dup) else float("nan")

    return {
        "pcap": nome,
        "porta_srv": porta,
        "portas_syn": len(portas_syn),
        "pacotes": len(df),
        "streams": int(df["tcp.stream"].nunique()),
        "porta_ok": f"{int(por_stream.sum())}/{len(por_stream)}",
        "sem_syn": len(sem_syn),
        "syn_nao_1o": int((tem_syn & ~primeiro_syn).sum()),
        "curtos_c_syn": len(curtos_ok),
        "pkts_min": int(n.min()),
        "pkts_max": int(n.max()),
        "dup_pct": round(100 * df["dup"].mean(), 1),
        "dup_dt_med_s": float(f"{dup_dt_med:.2g}") if pd.notna(dup_dt_med) else None,
        "clientes": ",".join(clientes),
        "hl_unicos": ",".join(str(int(x)) for x in sorted(df["hl"].dropna().unique())),
        "dur_s": round(df["frame.time_epoch"].max() - df["frame.time_epoch"].min(), 1),
    }


if __name__ == "__main__":
    arquivos = sorted(glob.glob("data/interim/*_packets.csv"))
    linhas = []
    for a in arquivos:
        try:
            linhas.append(checar(a))
        except Exception as e:  # um arquivo ruim não derruba os outros
            linhas.append({"pcap": os.path.basename(a), "erro": repr(e)[:80]})
    resumo = pd.DataFrame(linhas)
    pd.set_option(
        "display.width", 250, "display.max_columns", None, "display.max_colwidth", 60
    )
    print(resumo.to_string(index=False))
    resumo.to_csv("data/interim/checks_summary.csv", index=False)

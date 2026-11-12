import pandas as pd


def checar(caminho, nome, porta=8080):
    df = pd.read_csv(caminho)
    df["flags"] = df["tcp.flags"].apply(lambda x: int(x, 16))
    df = df.sort_values(["tcp.stream", "frame.time_epoch"])

    print(f"\n=== {nome} ===")
    print("pacotes, streams:", df.shape[0], df["tcp.stream"].nunique())

    # 1. ips
    print("src:", df["ipv6.src"].unique(), "dst:", df["ipv6.dst"].unique())

    # 2. portas: em cada pacote, exatamente um lado é a porta do servidor
    src_srv = df["tcp.srcport"] == porta
    dst_srv = df["tcp.dstport"] == porta
    df["um_lado"] = src_srv ^ dst_srv  # xor
    por_stream = df.groupby("tcp.stream")["um_lado"].all()
    print(
        "streams com regra por porta válida em todos os pacotes:",
        int(por_stream.sum()),
        "de",
        len(por_stream),
    )
    fora = por_stream.index[~por_stream.to_numpy()]
    print("streams fora da regra:", fora[:10].tolist())

    # 3. syn puro = bit 0x02 ligado e bit 0x10 desligado
    df["syn"] = ((df["flags"] & 0x02) != 0) & ((df["flags"] & 0x10) == 0)
    tem_syn = df.groupby("tcp.stream")["syn"].any()
    sem_syn = tem_syn.index[~tem_syn.to_numpy()]
    com_syn = tem_syn.index[tem_syn.to_numpy()]
    print("streams sem syn:", len(sem_syn), "de", len(tem_syn))

    # extra: quando começam os streams sem syn?
    t0 = df["frame.time_epoch"].min()
    ini = df.groupby("tcp.stream")["frame.time_epoch"].min() - t0
    print("início (s desde o 1º pacote) dos sem syn:")
    print(ini.loc[sem_syn].describe())
    print("início dos com syn (para comparar):")
    print(ini.loc[com_syn].describe())

    # extra: com syn, o syn é mesmo o primeiro pacote do stream?
    primeiro = df.groupby("tcp.stream")["syn"].first()
    print(
        "streams com syn cujo 1º pacote não é o syn:",
        int((tem_syn & ~primeiro).sum()),
    )

    # pacotes por stream (distribuição) e candidatos a fixture
    n = df.groupby("tcp.stream").size()
    print("pacotes por stream:")
    print(n.describe())
    print(n.value_counts().sort_index().head(15))
    curtos = n.index[(n < 8).to_numpy()]
    curtos_com_syn = [s for s in curtos if s in set(com_syn)]
    print("streams com < 8 pacotes:", len(curtos))
    print("... com syn (candidatos a fixture):", curtos_com_syn[:10])


checar("data/interim/taxa50_rep1_packets.csv", "ataque")
checar("data/interim/benigno_only_rep1_packets.csv", "benigno")

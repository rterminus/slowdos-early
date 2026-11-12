# Plano de execução: artigo de DDoS slow (disciplina e SBRC)

Nov 6, 2026 · @twrminus

## Resumo e alertas

Decisões fechadas: Hoeffding tree supervisionada na entrega de 18/11 e HST como segundo detector na versão completa para o SBRC.

- **Prazo:** 18/11 no SIGAA, sem prorrogação.
- **Pergunta (versão da disciplina):** como uma Hoeffding tree degrada, em recall com FPR fixa em 1%, à medida que a taxa de um ataque Slowloris/Slow HTTP diminui, vendo só os primeiros N pacotes do fluxo.
- **Exigências da disciplina:** 5 a 7 páginas (sem contar referências e anexos), 15 ou mais referências lidas, Anexo A (uso de IA), Anexo B (contribuições) e link do repositório no PDF.
- **Política de IA:** o texto é escrito pelo grupo; IA só apoia (revisão gramatical, organização de ideias, diagramas, código e tabelas) e todo uso é declarado no Anexo A. Os resumos de IA dos 44 artigos são só um mapa de leitura: cada um lê os trabalhos que vai citar.
- **SBRC (registro até 18/01):** o SBRC 2027 é presencial (17 a 21/05/2027, Foz do Iguaçu) e exige artigo inédito de até 14 páginas, incluindo resumo, figuras, diagramas e referências, no template SBC. O texto do chamado não traz o prazo de 18/01 nem diz se a avaliação é cega: conferir no site e no JEMS.

## Cronograma e divisão até 18/11

A dificuldade é média-alta para 12 dias (6 a 18/11): o risco está no testbed, nos dados e em escrever só no final. Por isso cada pessoa é dona de uma parte e escreve a seção correspondente.

| Papel | Responsável | Entregas | Depende de |
| --- | --- | --- | --- |
| P1: Testbed e captura | (Álvaro) | Apache em contêiner com poucos workers, slowhttptest, tcpdump, tráfego benigno; pcaps por taxa e repetição; contagem de conexões retidas | Nada (começa já) |
| P2: Dados e features | (Renan) | Extração dos N primeiros pacotes (Scapy/tshark), rótulos, CSV final, variante sem campos de cabeçalho para a ablação | Pcaps do P1 |
| P3: Modelo e avaliação | (Pedro) | Pipeline em River, Hoeffding tree em modo prequential, limiar para FPR de 1%, curvas de recall por taxa, ablação, sensibilidade de hiperparâmetros | CSV do P2 (até lá usa dados de teste) |
| P4: Literatura e escrita | (Letícia) | Overleaf com template SBC, Trabalhos Relacionados, 15 ou mais referências lidas, Introdução, Conclusão, Anexos A e B, log da busca | Nada (começa já) |

Cada pessoa escreve a seção do que fez (P1: Testbed e Metodologia; P2: Dados e Features; P3: Experimentos e Resultados; P4: Introdução, Trabalhos Relacionados e Conclusão) e revisa a de outra: P1 revisa P3, P2 revisa P4, P3 revisa P1, P4 revisa P2. O slide exige que todos conheçam o trabalho completo e participem do seminário, então a revisão cruzada também serve de estudo.

**Contrato de dados (decidir hoje):** pcaps nomeados `tipo_intervaloS_runK.pcap`; uma linha por fluxo no CSV, com `run_id`, `intervalo_s`, `rotulo`, atributos temporais e de tamanho dos primeiros N pacotes, e os campos de cabeçalho (TTL, IP ID, sequence, ACK, checksum) em colunas separadas para a ablação.

**Leituras (3 a 4 cada, com resumo próprio de 5 linhas):**

- P1: Tandon 2023, Demoulin 2019, Lukaseder 2018, artigo original da Hoeffding tree (Domingos e Hulten, *Mining High-Speed Data Streams*).
- P2: Giryes 2024, Ahmad e Truscan 2023, GTAE-IDS.
- P3: Hoeffding-ID, OFS-HAT, TDDEHT e o estudo de Hoeffding trees em DDoS para IoT.
- P4: Cambiaso 2020, Reed 2025, dissertação da FCUP (HST), Tan, Ting e Liu 2011.

**Cronograma:**

1. **Sex 6/11 (hoje):** reunião de 30 minutos para definir os responsáveis e o contrato de dados e criar o repositório e o projeto no Overleaf. Todos leem este doc.
2. **7 e 8/11 (sáb e dom):** P1 deixa Apache e slowhttptest funcionando, com **go/no-go no domingo**: o Slowloris precisa saturar o servidor (o nginx resiste por padrão). P2 roda a extração em um pcap de teste. P3 monta o pipeline em River com dados de teste. P4 cria o esqueleto das seções no Overleaf. Todos fazem suas leituras.
3. **9/11 (seg):** P1 entrega ao P2 as primeiras capturas (benigno e uma taxa).
4. **10/11 (ter, aula):** o grupo mostra à professora o testbed e o desenho do experimento e tira dúvidas (só são respondidas em aula).
5. **10 a 12/11:** P1 faz a varredura completa (\~6 taxas × \~5 repetições). P2 extrai tudo e gera o CSV final com a variante sem cabeçalhos. P3 faz uma avaliação preliminar. P4 escreve o rascunho da Introdução e dos Trabalhos Relacionados.
6. **12/11 (qui, aula):** checkpoint. Se os dados não estiverem completos, cortem taxas ou repetições em vez de adiar.
7. **13 a 15/11:** P3 fecha resultados e figuras. P1, P2 e P4 escrevem suas seções. O repositório fica organizado e com README.
8. **15 a 17/11:** P3 escreve Resultados e Discussão, P4 integra o texto e escreve a Conclusão, e acontece a revisão cruzada. A aula de 17/11 serve para dúvidas finais.
9. **18/11 (qua):** revisão final do PDF, Anexo A (declaração de IA), Anexo B (contribuições), link do repositório e entrega no SIGAA durante o dia, sem deixar para a noite. Não há prorrogação.

**Se o Slowloris não saturar o servidor no domingo:** trocar a configuração do Apache (menos workers) na segunda. Se ainda falhar, usar o CICIDS2017 (Slowloris e Slowhttptest) e, se servirem, os datasets públicos de Lukaseder, reduzindo a varredura a um estudo com menos taxas.

**Outros riscos:** tráfego benigno pouco realista pode inflar o desempenho (descrevam a escolha), e deixar a escrita para o fim estoura o prazo.

## Hoeffding tree: o que muda no G1

A Hoeffding tree é supervisionada, então a pergunta do G1 fica: **como uma Hoeffding tree degrada, em recall com FPR fixa em 1%, à medida que a taxa do Slowloris/Slow HTTP diminui, vendo só os primeiros N pacotes do fluxo?**

- **Encaixe na disciplina:** a árvore é a estrutura investigada, e a professora a recomendou e considerou suficiente o foco técnico. O recorte técnico inclui a sensibilidade a grace period e delta e o crescimento da árvore sob taxas baixas.
- **Gap reformulado:** já existem Hoeffding trees aplicadas a intrusão e DDoS (Hoeffding-ID, OFS-HAT, TDDEHT e um estudo para DDoS em IoT ligado ao projeto de Michele Nogueira Lima), então o artigo não pode dizer que a literatura é inexistente. A lacuna é Slowloris/Slow HTTP em L7, com fluxos parciais e varredura de taxa. Em uma busca rápida não achamos trabalho com esse escopo, mas a busca precisa ser sistemática e registrada (palavras-chave, filtros e data), como o slide pede.
- **HST na versão completa (SBRC):** é um detector de uma classe que precisa só de dados normais (Tan, Ting e Liu, 2011). A dissertação da FCUP obteve recall de 57,9% (Slowloris) e 28,4% (Slowhttptest) com FPR de 5,6%, o que é gap e risco ao mesmo tempo. Entra como comparador não supervisionado.
- **FPR em 1%:** ajustar o limiar de probabilidade da árvore em um conjunto de validação benigno.
- **Desenho do experimento:** treinar em uma taxa e testar nas demais mede a generalização; treinar com todas e avaliar por taxa mede o limite de detecção. Decidam isso no checkpoint de 10/11.

## Estratégia: construir em camadas, não escrever completo e enxugar

A melhor forma é fechar primeiro uma versão enxuta que já seja um artigo completo e válido, e expandi-la depois para o SBRC; escrever o artigo longo agora para cortar em seguida arrisca perder o prazo da disciplina, que não tem prorrogação.

1. **Camada 0 (até 18/11, disciplina):** pergunta única (G1 com Hoeffding tree), um testbed, \~6 taxas, uma ablação de cabeçalhos, 5 a 7 páginas, 15 ou mais referências lidas. Tudo que entrar aqui já vale para o SBRC.
2. **Camada 1 (19/11 a dezembro):** mais repetições, segundo detector (HST) para comparar supervisionado e não supervisionado, curva de impacto no servidor (janela de evasão efetiva), ablação completa (G2), outro servidor ou ferramenta de ataque. Os seminários (26/11 a 08/12) dão feedback de graça.
3. **Camada 2 (dezembro a 18/01):** Trabalhos Relacionados estendidos, discussão de limitações, pacote de reprodutibilidade, revisão interna e formatação no template SBC dentro do limite de 14 páginas, que inclui resumo, figuras, diagramas e referências (as 5 a 7 da disciplina não contam referências nem anexos, então escolham com cuidado quais extensões cabem), e seção não numerada “Disponibilidade de Artefatos” após a conclusão.

Para facilitar a expansão, organize o repositório e o LaTeX em módulos desde o início: scripts de captura, extração, modelo e análise separados, e uma seção do artigo por arquivo.

**Cuidados com a versão pública:**

- O PDF da disciplina precisa ter o link do repositório. O chamado do SBRC 2027 exige trabalho inédito, que não tenha sido publicado em outro lugar nem esteja sob revisão. Um relatório de disciplina entregue ao professor provavelmente não conta como publicação, mas não publiquem o PDF em arXiv ou no repositório antes da submissão, e confirmem com a coordenação do evento se houver dúvida. Código e dados podem ficar públicos: o SBRC incentiva ciência aberta, e o Comitê Técnico de Artefatos avalia os artefatos dos artigos aceitos. O chamado não fala de anonimato: conferir no site e no JEMS se a avaliação é cega.
- A política de IA da disciplina vale para o texto: escrevam vocês. Eu posso ajudar com planejamento, análise dos resultados, código, tabelas e diagramas, sempre declarados no Anexo A.

## Base bibliográfica: de \~50 resumos a uma base sólida

Uma base sólida se define pelo método, não pelo número: busca documentada, leitura do texto completo, cobertura de cada parte do gap e saturação das buscas. Os 44 resumos de IA e os 6 documentos auditados são ponto de partida; a tabela abaixo reúne candidatos achados em 07/11 por busca geral na web, **só com base em resumos, nada foi lido ainda**.

**Protocolo:**

1. **Triagem:** classificar as \~50 obras nos blocos A a D da tabela e marcar as \~15 que serão lidas por completo.
2. **Busca por bloco:** strings registradas com data, base e filtros, repetidas em IEEE Xplore, Scopus/Web of Science (via CAFe), Google Scholar e SOL (SBC). A busca de 07/11 foi na web aberta e não substitui essas bases.
3. **Snowballing:** referências e citações de cinco trabalhos-chave (Cambiaso 2020, Giryes 2024, Lukaseder 2018, Reed 2025 e o estudo de Hoeffding trees em DDoS para IoT).
4. **Verificação:** ler método e avaliação dos trabalhos marcados "não avaliado" no G1 e montar uma tabela que ligue cada afirmação do gap aos trabalhos que a sustentam.
5. **Critério de parada:** as buscas novas só devolvem trabalhos já conhecidos.

Meta: 15 ou mais lidas para a disciplina; para o SBRC, algo na faixa de 30 a 50 referências (estimativa minha, não regra do evento).

| Bloco | Candidatos | Por que importam | Cuidado |
| --- | --- | --- | --- |
| A: ataques lentos | Lukaseder et al. 2018 | Slowloris-ng (mais aleatório); intervalos padrão de 15 s no Slowloris e 30 s no slowhttptest | Verificar se os datasets abertos têm taxas variadas |
| A | Reed et al. 2025 (Minimal Overhead) | Diz que datasets existentes não capturam perfis stealth de slow DoS e sintetiza um dataset com ataques stealth-tuned | Ameaça ao ineditismo do G1; ler completo |
| A | Aiello, Cambiaso et al. 2013 | Slowloris com 100% de detecção e 1% de falso positivo, método estatístico | Ameaça ao G3; ler |
| A | Muraleedharan e Janet 2021 (ICT Express; SCAFFY) | Classificação supervisionada de slow HTTP em fluxos completos do CICIDS2017 | Serve de baseline supervisionado |
| A/E: dados | Catillo et al. (Univ. Sannio, JNCA 2022), SDN-SlowRate-DDoS (IEEE Access 2023), Kemp et al. 2020, estudo de Slow HTTP com amostragem (J. Big Data 2019) | Datasets de testbed e de rede real; desbalanceamento extremo | Checar licença e formato |
| A: Brasil | MENTORED-SBRC2024 (Slowloris), Faria et al. SBSeg 2019, Mascarenhas e Campos SBrT 2020 | Referências locais, que revisores do SBRC podem conhecer | Ler antes de citar |
| B: precoce | FIDS (ODU, 2025) | Features dos primeiros pacotes, mais de 99% de F1 e 99,17% de TPR a 0,01% de FPR em Slowloris e Slowhttptest | Ameaça a G3 e G4; fonte de menor nível (pesquisa de graduação): checar o dataset |
| B | Bernaille et al. (via Giryes), Ahmad et al. 2022 (ICSTW) | Clássico de classificação precoce e detecção precoce com deep learning | Achados por snowballing |
| C: stream | Hoeffding-ID (Yin 2016), OFS-HAT 2025, TDDEHT 2018, HT em DDoS IoT, Martindale et al. 2020, Carnier et al. | Hoeffding trees e HAT em IDS | Alguns são periódicos de menor impacto |
| C | Tan, Ting e Liu 2011 (HST), Kitsune (Mirsky et al.), ARES | Detectores online não supervisionados | Kitsune apareceu só na lista de referências de outro artigo |
| D: validade | Engelen et al. 2021, Lanvin et al., D'hooge et al. 2022, Apruzzese et al. 2023, Rosay et al. 2022 | Problemas do CICIDS2017 e shortcut learning (a porta de destino como atalho) | Base para o G2 e para a seção de ameaças à validade |
| D | Dois preprints de 2026 sobre shortcut learning | Registram TTL como artefato documentado | Não revisados: usar só como pista para achar as fontes originais |

**O que essa rodada muda nos gaps:** o G1 continua de pé, mas o Reed 2025 precisa ser lido antes de afirmar ineditismo. O G2 fica mais fraco, porque shortcut learning e o artefato de TTL já são documentados em NIDS em geral (o que falta é o recorte em Slowloris com poucos pacotes). O G3 e o G4 também ficam mais fracos por causa do Aiello 2013 e do FIDS, o que reforça tratar G3 e G4 como protocolo e configuração do experimento, não como contribuição.

**Log de busca (web aberta, WebSearch):** em 06/11, "Hoeffding tree intrusion detection data stream DDoS slowloris", "Half-Space Trees network intrusion detection streaming", "Half-Space Trees DDoS detection unsupervised online", "Half-Space Trees Slowloris slow DoS anomaly detection" e "Tan Ting Liu streaming anomaly detection half-space trees". Em 07/11, "slowloris detection evasion varying request rate sensitivity", "shortcut learning CICIDS2017 header features TTL network intrusion detection dataset artifacts", "early flow classification first packets slow HTTP DoS detection machine learning", "slow DoS dataset Slowloris Slow Read multiple attack configurations public dataset", "detecção ataques DoS lentos Slowloris aprendizado de máquina SBRC SBSeg" e "Hoeffding tree concept drift network intrusion detection stream learning DoS evaluation".

## Cronograma até o SBRC e plano B

Depois da entrega de 18/11 sobram cerca de 8 semanas até o prazo de registro do SBRC (18/01, informado por vocês). A trilha principal recebe cerca de 300 submissões por ano e aceita entre 30% e 35%, então o plano B é realista.

1. **18/11:** entrega da versão da disciplina (Camada 0).
2. **19/11 a 25/11:** slides do seminário (entrega em 25/11) e lista do que falta para a versão completa, a partir das perguntas da professora.
3. **26/11 a 08/12:** seminários; anotar as perguntas e críticas recebidas.
4. **Dezembro:** experimentos da Camada 1 (HST, impacto no servidor, ablação completa) e busca bibliográfica complementar sobre evasão de Slow HTTP e *shortcut learning* em CICIDS.
5. **Primeira quinzena de janeiro:** redigir a versão completa, revisão interna e formatação.
6. **Até 18/01:** submissão ao SBRC. Confirmem no site o prazo exato e se há etapa de registro de resumo (o texto do chamado não traz datas). O limite é de 14 páginas, incluindo resumo, figuras, diagramas e referências. Se o artigo for aceito, pelo menos um autor precisa se inscrever no SBRC 2027 e apresentá-lo presencialmente.

**Plano B (SBSeg):** se o SBRC não aceitar, o artigo já está modular e pode ser reenquadrado para segurança, com ênfase na janela de evasão e na ablação de cabeçalhos. A data do SBSeg seguinte precisa ser confirmada no chamado.

## Confirmações pendentes

Três itens estão confirmados; falta só conferir as regras do SBRC no chamado desta edição.

- [x] **Prazo:** 18/11, conforme o slide.
- [x] **Tema:** a professora recomendou a Hoeffding tree.
- [x] **Foco técnico:** suficiente para a disciplina, segundo o grupo.
- [ ] **SBRC:** o limite de 14 páginas está confirmado no chamado; falta conferir no site o prazo de 18/01, se a avaliação é cega e a política de IA generativa do Código de Conduta da SBC.

from __future__ import annotations
import argparse
import json
import logging
import re
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from river import tree
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve, precision_recall_curve
from statsmodels.stats.proportion import proportion_confint

LOGGER = logging.getLogger(__name__)
TARGET_FPR = 0.01
SCENARIOS = ('Global', 'Respondido')
GROUPS = ('A1', 'A2b', 'A3')
WINDOWS = (3, 4, 5, 6, 7, 8)
GRACE_PERIOD, DELTA, TAU = 50, 0.05, 0.2

def load_data(data_path: Path) -> pd.DataFrame:
    if not data_path.is_file():
        raise FileNotFoundError(f'CSV não encontrado: {data_path.resolve()}. Ajuste data_path.')
    raw = pd.read_csv(data_path)
    required = {'run_id', 'flow_type', 't_start', 'label', 'no_response'}
    missing = required - set(raw.columns)
    if missing:
        raise ValueError(f'Colunas obrigatórias ausentes: {sorted(missing)}')
    raw['flow_type'] = raw['flow_type'].astype(str).str.strip()
    raw['rep'] = pd.to_numeric(raw['run_id'].astype(str).str.extract(r'rep(\d+)')[0], errors='coerce')
    if raw['rep'].isna().any() or not raw['rep'].isin([1, 2, 3]).all():
        raise ValueError('run_id deve identificar rep1, rep2 ou rep3 em todos os registros.')
    if raw[['label','no_response']].isna().any().any():
        raise ValueError('label e no_response não podem conter valores ausentes.')
    if not set(raw['label'].unique()).issubset({0, 1}) or not set(raw['no_response'].unique()).issubset({0, 1}):
        raise ValueError('label e no_response devem ser binários (0/1).')
    raw['rep'] = raw['rep'].astype(int)
    raw['_healthy'] = raw['flow_type'].eq('benign')
    raw['_phase'] = np.select([
        (raw.rep == 1) & (~raw._healthy),
        (raw.rep == 1) & raw._healthy,
        raw.rep.isin([2, 3])], ['train', 'calibration', 'test'], default='invalid')
    raw = raw.sort_values(['rep', 't_start', 'run_id'], kind='stable').reset_index(drop=True)
    return raw

import re

def feature_columns(df, n, group):
    prefixes = {'A1': ('b_',), 'A2b': ('b_', 'f_flags_'),
                'A3': ('b_', 'f_flags_', 'f_retrans_')}[group]
    selected = []
    for col in df.columns:
        if not col.startswith(prefixes):
            continue
        m = re.search(r'_(\d+)$', col)
        if m and 1 <= int(m.group(1)) <= n:
            selected.append(col)
    if not selected:
        raise ValueError(f'Sem features para {group}, N={n}. Verifique os nomes das colunas.')
    return selected

def to_x(row, cols):
    x = {}
    for c in cols:
        val = row[c]
        if pd.isna(val):
            continue
        if c.startswith(('f_flags_', 'f_retrans_')):
            x[c] = str(int(float(val)))
        else:
            x[c] = float(val)
    return x

def model_new(cols, grace_period=GRACE_PERIOD, delta=DELTA, tau=TAU):
    nominal = [c for c in cols if c.startswith(('f_flags_', 'f_retrans_'))]
    return tree.HoeffdingTreeClassifier(grace_period=grace_period,
        delta=delta, tau=tau, leaf_prediction='mc', nominal_attributes=nominal)

def predict_scores(model, df, cols):
    scores = []
    for row in df[cols].itertuples(index=False, name=None):
        x = {c: (str(int(float(v))) if c.startswith(('f_flags_', 'f_retrans_')) else float(v))
             for c, v in zip(cols, row) if pd.notna(v)}
        scores.append(float(model.predict_proba_one(x).get(1, 0.0)))
    return np.asarray(scores)

def train_model(model, df, cols):
    for values in df[cols + ['label']].itertuples(index=False, name=None):
        x = {c: (str(int(float(v))) if c.startswith(('f_flags_', 'f_retrans_')) else float(v))
             for c, v in zip(cols, values[:-1]) if pd.notna(v)}
        model.learn_one(x, int(values[-1]))
    return model

def calibrated_threshold(benign_scores, alpha=0.01):
    # Limiar conservador: para classificação score > threshold, garante
    # empiricamente <= alpha falsos positivos no conjunto de calibração.
    s = np.sort(np.asarray(benign_scores, dtype=float))
    if not len(s):
        raise ValueError('Calibração sem exemplos benignos.')
    k = int(np.floor(alpha * len(s)))
    if k == 0:
        return float(s[-1])
    return float(s[-k-1])

def wilson(k, total):
    if total == 0:
        return (np.nan, np.nan)
    return tuple(map(float, proportion_confint(k, total, alpha=0.05, method='wilson')))

def metrics(y, scores, threshold):
    y = np.asarray(y, dtype=int)
    pred = (np.asarray(scores) > threshold).astype(int)
    tp = int(((y == 1) & (pred == 1)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    tn = int(((y == 0) & (pred == 0)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    pos, neg = tp + fn, fp + tn
    rec_ci = wilson(tp, pos)
    fpr_ci = wilson(fp, neg)
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, N_attack=pos, N_benign=neg,
        Recall=tp/pos if pos else np.nan,
        Recall_CI_low=rec_ci[0], Recall_CI_high=rec_ci[1],
        FPR=fp/neg if neg else np.nan,
        FPR_CI_low=fpr_ci[0], FPR_CI_high=fpr_ci[1],
        Precision=tp/(tp+fp) if tp+fp else np.nan,
        Specificity=tn/neg if neg else np.nan,
        F1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else np.nan,
        ROC_AUC=roc_auc_score(y, scores) if len(np.unique(y)) == 2 else np.nan,
        PR_AUC=average_precision_score(y, scores) if pos else np.nan)


def run_experiment(raw: pd.DataFrame, out_dir: Path, target_fpr: float = TARGET_FPR, grace_period: int = GRACE_PERIOD, delta: float = DELTA, tau: float = TAU):
    rows, breakdown, predictions = [], [], []
    for scenario in SCENARIOS:
        df = raw if scenario == 'Global' else raw.loc[raw.no_response.eq(0)].copy()
        train = df.loc[df._phase.eq('train')]
        cal = df.loc[df._phase.eq('calibration') & df.label.eq(0)]
        test = df.loc[df._phase.eq('test')]
        if len(train) == 0 or len(cal) == 0 or len(test) == 0:
            raise ValueError(f'Fase vazia no cenário {scenario}.')
        if train.label.nunique() < 2:
            raise ValueError(f'Treinamento do cenário {scenario} não contém as duas classes.')
        for group in GROUPS:
            for N in WINDOWS:
                cols = feature_columns(df, N, group)
                model = train_model(model_new(cols, grace_period, delta, tau), train, cols)
                cal_scores = predict_scores(model, cal, cols)
                threshold = calibrated_threshold(cal_scores, target_fpr)
                scores = predict_scores(model, test, cols)
                yy = test.label.to_numpy(dtype=int)
                main = metrics(yy, scores, threshold)
                cal_fpr = float(np.mean(cal_scores > threshold))
                key = dict(Scenario=scenario, Ablation=group, N=N)
                rows.append({**key, 'Features':len(cols), 'Train_n':len(train),
                    'Calibration_n':len(cal), 'Test_n':len(test), 'Threshold':threshold,
                    'FPR_calibration':cal_fpr, **main,
                    'FPR_le_1pct':bool(np.isfinite(main['FPR']) and main['FPR'] <= target_fpr),
                    'FPR_CI_upper_le_1pct':bool(np.isfinite(main['FPR_CI_high']) and main['FPR_CI_high'] <= target_fpr)})
                detail = test[['rep','flow_type','label','no_response']].copy()
                detail['p_attack'] = scores
                detail['pred'] = (scores > threshold).astype(int)
                detail['Scenario'], detail['Ablation'], detail['N'] = scenario, group, N
                predictions.append(detail)
                for name, mask in [('rep2', test.rep.eq(2)), ('rep3', test.rep.eq(3)),
                                   ('healthy', test._healthy), ('under_attack', ~test._healthy)]:
                    if mask.any():
                        sub = metrics(yy[mask.to_numpy()], scores[mask.to_numpy()], threshold)
                        breakdown.append({**key, 'Subset':name, **sub})
            LOGGER.info('Concluído: %s | %s', scenario, group)

    results = pd.DataFrame(rows)
    strata = pd.DataFrame(breakdown)
    predictions_df = pd.concat(predictions, ignore_index=True)
    results.to_csv(out_dir/'metricas_36_configuracoes.csv', index=False)
    strata.to_csv(out_dir/'metricas_estratificadas.csv', index=False)
    predictions_df.to_csv(out_dir/'previsoes_teste.csv', index=False)
    return results, strata, predictions_df

def save_plots(results, predictions_df, out_dir: Path, target_fpr: float = TARGET_FPR):
    plt.rcParams.update({'figure.dpi':120, 'savefig.dpi':180})
    fig, axes = plt.subplots(2, 2, figsize=(13, 9), constrained_layout=True)
    for (sc, gr), d in results.groupby(['Scenario','Ablation'], sort=False):
        d = d.sort_values('N')
        label = f'{sc} / {gr}'
        axes[0,0].plot(d.N, d.Recall, marker='o', label=label)
        axes[0,1].plot(d.N, d.FPR, marker='o', label=label)
        axes[1,0].scatter(d.FPR, d.Recall, label=label)
        axes[1,1].plot(d.N, d.ROC_AUC, marker='o', label=label)
    axes[0,0].set(title='Recall dos ataques', ylabel='Recall', xlabel='Pacotes observados (N)', ylim=(-.02,1.02))
    axes[0,1].set(title='FPR em todos os benignos do teste', ylabel='FPR', xlabel='Pacotes observados (N)')
    axes[0,1].axhline(target_fpr, linestyle='--', color='black', label='Meta 1%')
    axes[1,0].set(title='Compromisso Recall × FPR', xlabel='FPR', ylabel='Recall', ylim=(-.02,1.02))
    axes[1,0].axvline(target_fpr, linestyle='--', color='black')
    axes[1,1].set(title='ROC-AUC', xlabel='Pacotes observados (N)', ylabel='ROC-AUC', ylim=(-.02,1.02))
    for ax in axes.flat:
        ax.grid(alpha=.25)
    handles, labels = axes[0,0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='outside lower center', ncol=3)
    fig.savefig(out_dir/'painel_principal.pdf', bbox_inches='tight')
    fig.savefig(out_dir/'painel_principal.png', bbox_inches='tight')
    plt.close(fig)

    fig2, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), constrained_layout=True)
    for scenario in SCENARIOS:
        sub = predictions_df.loc[(predictions_df.Scenario == scenario) &
            (predictions_df.Ablation == 'A3') & (predictions_df.N == 8)]
        y, s = sub.label.to_numpy(), sub.p_attack.to_numpy()
        if len(np.unique(y)) == 2:
            fpr, tpr, _ = roc_curve(y, s)
            precision, recall, _ = precision_recall_curve(y, s)
            ax1.plot(fpr, tpr, label=scenario)
            ax2.plot(recall, precision, label=scenario)
    ax1.axvline(target_fpr, color='black', linestyle='--', label='FPR 1%')
    ax1.set(title='ROC — A3, N=8 (pré-especificado)', xlabel='FPR', ylabel='TPR', xlim=(0,1), ylim=(0,1))
    ax2.set(title='Precisão–Recall — A3, N=8', xlabel='Recall', ylabel='Precisão', xlim=(0,1), ylim=(0,1))
    for ax in (ax1, ax2):
        ax.grid(alpha=.25)
        ax.legend()
    fig2.savefig(out_dir/'curvas_roc_pr.pdf', bbox_inches='tight')
    fig2.savefig(out_dir/'curvas_roc_pr.png', bbox_inches='tight')
    plt.close(fig2)
def main(argv=None):
    parser = argparse.ArgumentParser(description='Experimento HTC clássica: detecção precoce com FPR <= 1%.')
    parser.add_argument('--data', type=Path, required=True, help='CSV de fluxos com rep1, rep2 e rep3')
    parser.add_argument('--output', type=Path, default=Path('resultados_htc_classica'))
    parser.add_argument('--target-fpr', type=float, default=TARGET_FPR)
    parser.add_argument('--grace-period', type=int, default=GRACE_PERIOD)
    parser.add_argument('--delta', type=float, default=DELTA)
    parser.add_argument('--tau', type=float, default=TAU)
    args = parser.parse_args(argv)
    if not 0 < args.target_fpr < 1:
        parser.error('--target-fpr deve estar entre 0 e 1 (exclusivo).')
    if args.grace_period <= 0 or not 0 < args.delta < 1 or not 0 <= args.tau <= 1:
        parser.error('Parâmetros inválidos da Hoeffding Tree.')
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    args.output.mkdir(parents=True, exist_ok=True)
    raw = load_data(args.data)
    LOGGER.info('Dados: %d fluxos; fases: %s', len(raw), raw['_phase'].value_counts().to_dict())
    results, strata, predictions_df = run_experiment(raw, args.output, args.target_fpr, args.grace_period, args.delta, args.tau)
    save_plots(results, predictions_df, args.output, args.target_fpr)
    (args.output/'configuracao.json').write_text(json.dumps({'data':str(args.data.resolve()),'target_fpr':args.target_fpr,'grace_period':args.grace_period,'delta':args.delta,'tau':args.tau,'groups':GROUPS,'windows':WINDOWS,'train':'rep1 under_attack','calibration':'rep1 benign','test':'rep2 and rep3, frozen model','leaf_prediction':'mc'},indent=2,ensure_ascii=False),encoding='utf-8')
    LOGGER.info('Configurações com FPR <= %.2f%%: %d/%d', args.target_fpr*100, int(results['FPR_le_1pct'].sum()), len(results))
    LOGGER.info('Resultados em: %s', args.output.resolve())

if __name__ == '__main__':
    main()

# LightGBM Training Report

## Integrity

- Training used only the eight real local CIC-IDS2017 CSV files; no synthetic data was generated or used.
- The original CIC-IDS2017 files were opened read-only and were not modified.
- Input feature order came exclusively from `artifacts/feature_schema.json` and was preserved in `artifacts/model_feature_schema.json`.

## Dataset and split

- Source rows: 2,830,743
- Exact duplicate full records removed before splitting: 308,381
- Rows used for split/training: 2,522,362
- Features: 78 (all retained, including both physical ` Fwd Header Length` positions)
- Label column: ` Label`
- Train / validation / test: 1,765,653 / 378,354 / 378,355
- Split strategy: two fixed-seed stratified splits (70% / 15% / 15%). Full-record deduplication was performed before splitting to reduce identical-record leakage.

## Preprocessing

- Positive and negative infinity were converted to `NaN`.
- `SimpleImputer(strategy='median')` was fit only on the training partition, then applied to validation and test partitions.
- `LabelEncoder` was fit on training labels and saved with its exact class order.
- No scaling or feature selection was applied. LightGBM does not require feature scaling.
- `class_weight='balanced'` was used during training; no synthetic oversampling was used.

## LightGBM configuration

```json
{
  "objective": "multiclass",
  "num_class": 15,
  "n_estimators": 400,
  "learning_rate": 0.08,
  "num_leaves": 31,
  "max_depth": -1,
  "subsample": 0.9,
  "colsample_bytree": 0.9,
  "reg_lambda": 1.0,
  "class_weight": "balanced",
  "random_state": 20260817,
  "n_jobs": -1,
  "deterministic": true,
  "force_col_wise": true,
  "verbosity": -1
}
```
- Best iteration selected by validation multi-logloss / early stopping: 289

## Held-out test metrics

- accuracy: 0.998636
- macro_precision: 0.912550
- macro_recall: 0.936370
- macro_f1: 0.922285
- weighted_precision: 0.998775
- weighted_recall: 0.998636
- weighted_f1: 0.998681

## Per-class held-out results

| Class | Precision | Recall | F1-score | Support |
| --- | ---: | ---: | ---: | ---: |
| `BENIGN` | 0.999968 | 0.998928 | 0.999448 | 314,473 |
| `Bot` | 0.687204 | 0.989761 | 0.811189 | 293 |
| `DDoS` | 0.999584 | 0.999896 | 0.999740 | 19,203 |
| `DoS GoldenEye` | 0.989082 | 0.998056 | 0.993548 | 1,543 |
| `DoS Hulk` | 0.998189 | 0.999267 | 0.998728 | 25,928 |
| `DoS Slowhttptest` | 0.984810 | 0.992347 | 0.988564 | 784 |
| `DoS slowloris` | 0.993820 | 0.995050 | 0.994434 | 808 |
| `FTP-Patator` | 1.000000 | 1.000000 | 1.000000 | 890 |
| `Heartbleed` | 1.000000 | 1.000000 | 1.000000 | 1 |
| `Infiltration` | 1.000000 | 1.000000 | 1.000000 | 5 |
| `PortScan` | 0.989461 | 0.999339 | 0.994376 | 13,623 |
| `SSH-Patator` | 0.997934 | 1.000000 | 0.998966 | 483 |
| `Web Attack � Brute Force` | 0.709360 | 0.654545 | 0.680851 | 220 |
| `Web Attack � Sql Injection` | 1.000000 | 1.000000 | 1.000000 | 3 |
| `Web Attack � XSS` | 0.338843 | 0.418367 | 0.374429 | 98 |

## Confusion matrix

Rows are actual classes; columns are predicted classes. Class order:

```text
0: BENIGN
1: Bot
2: DDoS
3: DoS GoldenEye
4: DoS Hulk
5: DoS Slowhttptest
6: DoS slowloris
7: FTP-Patator
8: Heartbleed
9: Infiltration
10: PortScan
11: SSH-Patator
12: Web Attack � Brute Force
13: Web Attack � Sql Injection
14: Web Attack � XSS
```

```text
314136 132 8 3 40 9 3 0 0 0 140 1 0 0 1
3 290 0 0 0 0 0 0 0 0 0 0 0 0 0
2 0 19201 0 0 0 0 0 0 0 0 0 0 0 0
0 0 0 1540 2 1 0 0 0 0 0 0 0 0 0
0 0 0 14 25909 0 0 0 0 0 5 0 0 0 0
2 0 0 0 1 778 2 0 0 0 0 0 1 0 0
1 0 0 0 0 2 804 0 0 0 0 0 0 0 1
0 0 0 0 0 0 0 890 0 0 0 0 0 0 0
0 0 0 0 0 0 0 0 1 0 0 0 0 0 0
0 0 0 0 0 0 0 0 0 5 0 0 0 0 0
1 0 0 0 4 0 0 0 0 0 13614 0 2 0 2
0 0 0 0 0 0 0 0 0 0 0 483 0 0 0
0 0 0 0 0 0 0 0 0 0 0 0 144 0 76
0 0 0 0 0 0 0 0 0 0 0 0 0 3 0
1 0 0 0 0 0 0 0 0 0 0 0 56 0 41
```

## Warnings and limitations

- Very rare classes (especially Heartbleed, Infiltration, and Web Attack SQL Injection) have tiny held-out supports. Their per-class metrics are reported above and must be interpreted with caution.
- Full-record deduplication reduces identical-record leakage but does not alter the original files or the 78-feature schema.
- This phase does not implement prediction APIs, SHAP, packet capture, a frontend, or real-time monitoring.

## Artifact validation

- Reloaded model reports `n_features_in_ = 78`.
- Reloaded median imputer reports `n_features_in_ = 78`.
- Reloaded label encoder contains 15 classes in the recorded order.
- The training run also transformed and predicted a real five-row held-out batch before artifacts were written.

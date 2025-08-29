import pandas as pd, numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score

df = pd.read_csv("scan_eval.csv")
df = df[df["label"].isin(["fake","legit"])].copy()
y_true = (df["label"]=="fake").astype(int).values
y_score = df["probability"].values

print("ROC-AUC:", roc_auc_score(y_true, y_score))
thr = 0.5
y_pred = (y_score >= thr).astype(int)
print("Confusion @0.5:\\n", confusion_matrix(y_true, y_pred))
print(classification_report(y_true, y_pred, digits=4))

ths = np.linspace(0,1,101)
f1s = [f1_score(y_true, (y_score>=t).astype(int)) for t in ths]
best_t = ths[int(np.argmax(f1s))]
print("Best F1 threshold:", best_t)
y_pred_b = (y_score >= best_t).astype(int)
print("Confusion @best F1:\\n", confusion_matrix(y_true, y_pred_b))
print(classification_report(y_true, y_pred_b, digits=4))

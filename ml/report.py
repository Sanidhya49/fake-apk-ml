"""Concurrent folder scan and Excel report with metrics.

Usage:
    python -m ml.report --input data --output artifacts/scan_report.xlsx --workers 10 --quick
"""

import argparse
import concurrent.futures as cf
import os
import time
from typing import List, Dict

import pandas as pd
import requests


def iter_files(root: str) -> List[str]:
    exts = (".apk", ".APK", ".apks", ".APKS", ".xapk", ".XAPK")
    paths: List[str] = []
    for r, _d, files in os.walk(root):
        for f in files:
            if f.endswith(exts):
                paths.append(os.path.join(r, f))
    return paths


def label_from_path(p: str) -> str:
    p2 = p.replace("\\", "/").lower()
    if "/data/fake/" in p2:
        return "fake"
    if "/data/legit/" in p2:
        return "legit"
    return "unknown"


def scan_file(api_url: str, path: str, quick: bool) -> Dict:
    with open(path, "rb") as f:
        files = {"file": (os.path.basename(path), f)}
        resp = requests.post(f"{api_url}/scan", params={"quick": str(quick).lower()}, files=files, timeout=180)
    j = resp.json()
    j["path"] = path
    j["label"] = label_from_path(path)
    fv = j.get("feature_vector", {})
    # Enrich report with a few columns for Excel
    j["count_suspicious"] = fv.get("count_suspicious", 0)
    j["impersonation_score"] = fv.get("impersonation_score", 0)
    j["cert_present"] = fv.get("cert_present", 0)
    j["issuer_present"] = fv.get("issuer_present", 0)
    j["num_domains"] = fv.get("num_domains", 0)
    return j


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Folder with APKs")
    ap.add_argument("--output", default=os.path.join("artifacts", "scan_report.xlsx"))
    ap.add_argument("--api", default="http://localhost:9000")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    files = iter_files(args.input)
    rows: List[Dict] = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(scan_file, args.api, p, args.quick) for p in files]
        for fut in cf.as_completed(futs):
            try:
                rows.append(fut.result())
            except Exception as e:
                rows.append({"path": "<error>", "error": str(e)})
    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    # Save Excel with a metrics sheet if labels exist
    with pd.ExcelWriter(args.output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="scans")
        try:
            sub = df[df["label"].isin(["fake","legit"])].copy()
            if not sub.empty:
                from sklearn.metrics import classification_report, confusion_matrix, f1_score
                y_true = (sub["label"] == "fake").astype(int).values
                y_pred = (sub["probability"] >= 0.61).astype(int).values
                cr = classification_report(y_true, y_pred, output_dict=True)
                cm = confusion_matrix(y_true, y_pred)
                met = pd.DataFrame(cr).T
                met.to_excel(writer, sheet_name="metrics")
                pd.DataFrame(cm, columns=["pred_0","pred_1"], index=["true_0","true_1"]).to_excel(writer, sheet_name="confusion")
                # Summary by risk
                sub.groupby("risk").size().to_frame("count").to_excel(writer, sheet_name="risk_summary")
        except Exception:
            pass
    print(f"Wrote {args.output} in {time.time()-t0:.1f}s for {len(files)} files")


if __name__ == "__main__":
    main()




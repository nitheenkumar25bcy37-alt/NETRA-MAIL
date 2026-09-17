"""Offline concurrent full-pipeline measurement; not hosted HTTP capacity."""
import argparse,json,os,math,time,statistics
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from evaluation.evaluate_v2 import OfflineIPs,OfflineDomains
from backend.services.analysis_orchestrator import AnalysisOrchestrator

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--count",type=int,default=100);parser.add_argument("--workers",type=int,default=10);parser.add_argument("--output",type=Path,default=Path("evaluation_results/upgrades/load.json"));a=parser.parse_args()
    cases=json.loads(Path(".local-corpora/test.json").read_text())[:a.count]
    analyzer=AnalysisOrchestrator(ip_provider=OfflineIPs(),domain_provider=OfflineDomains())
    def run(case):
        started=time.perf_counter()
        try:
            result=analyzer.analyze((Path(".local-corpora")/case["path"]).read_bytes())
            return {"seconds":time.perf_counter()-started,"error":None,"skipped_attachments":sum(bool(x.get("analysis_skipped")) for x in result.parsed.get("attachments",[]))}
        except Exception as exc:return {"seconds":time.perf_counter()-started,"error":type(exc).__name__,"error_detail":str(exc)[:200]}
    with patch.dict(os.environ,{"NETRA_URL_REPUTATION_ENABLED":"false","NETRA_EXPAND_SHORT_URLS":"0"}),patch("backend.email_authentication.EmailAuthenticationVerifier._arc",return_value={"status":"unavailable","source":"offline"}),patch("backend.dkim_verifier.DKIMVerifier.verify",return_value={"status":"unavailable","source":"offline"}):
        started=time.perf_counter()
        with ThreadPoolExecutor(max_workers=a.workers) as pool: rows=list(pool.map(run,cases))
        elapsed=time.perf_counter()-started
    values=sorted(r["seconds"] for r in rows)
    report={"pipeline_version":analyzer.VERSION,"messages":len(rows),"concurrency":a.workers,"errors":sum(bool(r["error"]) for r in rows),"error_details":[r for r in rows if r["error"]],"skipped_attachments":sum(r.get("skipped_attachments",0) for r in rows),"wall_seconds":elapsed,"throughput_per_second":len(rows)/elapsed,"p50_seconds":statistics.median(values),"p95_seconds":values[math.ceil(len(values)*.95)-1],"p99_seconds":values[math.ceil(len(values)*.99)-1],"scope":"Local offline full pipeline; DNS, DKIM DNS, ARC and external reputation/expansion disabled. Includes worker availability limits; not a Render HTTP load test."}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
if __name__=="__main__":main()

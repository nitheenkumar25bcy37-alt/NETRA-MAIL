"""Compare URL scores with threshold selected only on validation domains."""
import csv,json
from pathlib import Path
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from backend.url_analyzer import URLAnalyzer

def metrics(rows,threshold):
    tp=tn=fp=fn=0
    for row in rows:
        predicted=float(row["risk_score"])>=threshold;actual=row["actual"]=="PHISHING"
        tp+=predicted and actual;tn+=not predicted and not actual;fp+=predicted and not actual;fn+=not predicted and actual
    ratio=lambda a,b:a/b if b else None
    return {"tp":tp,"tn":tn,"fp":fp,"fn":fn,"precision":ratio(tp,tp+fp),"recall":ratio(tp,tp+fn),"f1":ratio(2*tp,2*tp+fp+fn),"false_positive_rate":ratio(fp,fp+tn),"accuracy":ratio(tp+tn,len(rows))}
def main():
    root=Path("evaluation_results/upgrades")
    before=list(csv.DictReader((root/"baseline_url/url_results.csv").open(encoding="utf-8-sig")))
    after=list(csv.DictReader((root/"final_url/url_results.csv").open(encoding="utf-8-sig")))
    assert [(r["url"],r["actual"]) for r in before]==[(r["url"],r["actual"]) for r in after]
    groups=[URLAnalyzer._base_domain(urlparse(r["url"]).hostname or r["url"]) for r in before]
    validation,test=next(GroupShuffleSplit(n_splits=1,test_size=.8,random_state=26106).split(before,groups=groups))
    thresholds=list(range(10,81,5));development=[before[i] for i in validation]
    threshold=max(thresholds,key=lambda t:metrics(development,t)["f1"] or 0)
    result={"threshold":threshold,"validation_samples":len(validation),"test_samples":len(test),"baseline":metrics([before[i] for i in test],threshold),"final":metrics([after[i] for i in test],threshold),"scope":"Threshold selected on separate validation domain groups, unchanged for final test comparison.","limitations":["Fixed historical PhishTank/Tranco sample; URL model training overlap is not excluded.","Grouping uses the project registrable-domain heuristic. This is not full-email accuracy or proof of performance on today's threats."]}
    (root/"threshold_holdout_url.json").write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=="__main__":main()

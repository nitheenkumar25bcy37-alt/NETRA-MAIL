"""Fit Platt scaling on calibration messages without retraining the base model."""
import hashlib,json,math
from pathlib import Path
from email import policy
from email.parser import BytesParser
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss,log_loss
from backend.ml_classifier import LocalMLClassifier

def text(raw):
    from backend.parser import ForensicEmailParser
    from backend.services.email_features import email_feature_text
    msg=BytesParser(policy=policy.default).parsebytes(raw)
    parser=ForensicEmailParser();plain,html=parser._extract_bodies(msg)
    visible=parser._extract_html_details(html)["visible_text"]
    return email_feature_text({"metadata":{"subject":str(msg.get("Subject","")).strip(),"from":str(msg.get("From","")).strip()},"body":{"plain":plain,"visible_text":visible}})
def rows(name):
    root=Path(".local-corpora")
    manifest=json.loads((root/(name+".json")).read_text())
    model=LocalMLClassifier._load(); index=list(model.classes_).index("PHISHING")
    probabilities=[];labels=[]
    for row in manifest:
        probabilities.append(float(model.predict_proba([text((root/row["path"]).read_bytes())])[0][index]));labels.append(int(row["malicious"]))
    return np.clip(probabilities,1e-6,1-1e-6),np.array(labels)
def main():
    p,y=rows("calibration");x=np.log(p/(1-p)).reshape(-1,1)
    # Internal split decides activation; held-out test does not tune parameters.
    split=np.arange(len(y))%5!=0
    candidate=LogisticRegression(C=1).fit(x[split],y[split])
    held=candidate.predict_proba(x[~split])[:,1]
    approved=brier_score_loss(y[~split],held)<brier_score_loss(y[~split],p[~split])
    model=LogisticRegression(C=1).fit(x,y)
    params={"method":"Platt scaling","slope":float(model.coef_[0,0]),"intercept":float(model.intercept_[0]),"model_sha256":hashlib.sha256(LocalMLClassifier.MODEL_PATH.read_bytes()).hexdigest(),"samples":len(y),"activated":bool(approved),"limitations":["Cross-corpus source and time shift; exact hashes disjoint, template overlap not excluded."]}
    (LocalMLClassifier.MODEL_PATH.parent/"email_probability_calibration.json").write_text(json.dumps(params,indent=2))
    t,z=rows("test");cal=model.predict_proba(np.log(t/(1-t)).reshape(-1,1))[:,1]
    report={"activated":bool(approved),"calibration_samples":len(y),"test_samples":len(z),"validation_brier_before":brier_score_loss(y[~split],p[~split]),"validation_brier_after":brier_score_loss(y[~split],held),"test_brier_before":brier_score_loss(z,t),"test_brier_after":brier_score_loss(z,cal),"test_logloss_before":log_loss(z,t),"test_logloss_after":log_loss(z,cal),"scope":"ML probability only, same plain/visible-HTML features as production. Optional image OCR excluded from calibration."}
    Path("evaluation_results/upgrades/calibration.json").write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
if __name__=="__main__":main()

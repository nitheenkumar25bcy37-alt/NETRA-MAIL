"""Fetch primary-source email corpora; retain raw data locally, commit only metrics."""
import argparse, hashlib, io, json, mailbox, random, tarfile
from pathlib import Path
import requests

SOURCES = {"phishing": "https://monkey.org/~jose/phishing/phishing-2025", "ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"}
def download(url):
    with requests.get(url, timeout=(10,30), stream=True) as response:
        response.raise_for_status()
        content=bytearray()
        for chunk in response.iter_content(65536):
            content.extend(chunk)
            if len(content)>32*1024*1024: raise ValueError("Corpus exceeds 32MB")
        return bytes(content)
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--root",type=Path,default=Path(".local-corpora")); args=parser.parse_args()
    root=args.root; root.mkdir(parents=True,exist_ok=True); groups={}
    provenance={}
    for kind,url in SOURCES.items():
        data=download(url); provenance[kind]={"url":url,"sha256":hashlib.sha256(data).hexdigest()}
        rows=[]
        if kind=="phishing":
            path=root/"nazario.mbox";path.write_bytes(data)
            box=mailbox.mbox(path)
            rows=[m.as_bytes() for m in box];box.close()
        else:
            with tarfile.open(fileobj=io.BytesIO(data),mode="r:bz2") as archive:
                for member in archive:
                    if member.isfile() and member.size<2*1024*1024 and not member.name.endswith("cmds"):
                        rows.append(archive.extractfile(member).read())
        unique={hashlib.sha256(raw).hexdigest():raw for raw in rows}
        items=sorted(unique.items());random.Random(26106).shuffle(items)
        if len(items)<200: raise ValueError("Insufficient unique messages")
        groups[kind]=items[:200]
    calibration=[];test=[]
    for kind,items in groups.items():
        for index,(digest,raw) in enumerate(items):
            name=f"{digest}.eml";(root/name).write_bytes(raw)
            row={"path":name,"malicious":kind=="phishing","source":kind,"sha256":digest}
            (calibration if index<100 else test).append(row)
    for name,rows in [("calibration",calibration),("test",test)]:
        (root/(name+".json")).write_text(json.dumps(rows,indent=2))
    (root/"provenance.json").write_text(json.dumps(provenance,indent=2))
    print("Prepared 200 calibration and 200 test emails from disjoint message hashes. Source shift and template overlap remain limitations.")
if __name__=="__main__": main()

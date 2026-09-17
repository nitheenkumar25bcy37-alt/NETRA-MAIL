"""One entry point for reproducible NETRA regression and offline benchmark checks."""
import argparse,subprocess,sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument("--public-corpus",action="store_true",help="Download/reuse public email samples and run email/latency benchmarks");a=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    commands=[["-m","pytest","tests","-q"],["-m","evaluation.evaluate_v2","--output","evaluation_results/upgrades/reproduced_synthetic.json"]]
    if a.public_corpus:
        if not (root/".local-corpora/test.json").exists():commands.append(["-m","evaluation.prepare_public_emails"])
        commands.extend([["-m","evaluation.evaluate_v2","--manifest",".local-corpora/test.json","--threshold","35","--output","evaluation_results/upgrades/reproduced_public.json"],["-m","evaluation.load_pipeline","--count","100","--workers","10","--output","evaluation_results/upgrades/reproduced_load.json"]])
    for command in commands:subprocess.run([sys.executable]+command,cwd=root,check=True)
    print("Completed selected validation phases. Read the report scopes before quoting metrics.")
if __name__=="__main__":main()

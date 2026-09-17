"""Curated phrase-similarity model. No network calls or pretrained embeddings."""
import re
from functools import lru_cache
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from backend.schemas.findings import Finding
from backend.compliance import IndiaPrivacyPreserver

EXAMPLES = [
 ("credential", "confirm your password and verification code to prevent your account from being suspended"),
 ("credential", "sign in and verify your account immediately or access will be disabled"),
 ("credential", "provide your login details within twenty four hours to avoid account closure"),
 ("credential", "validate your identity now to restore access to your account"),
 ("payment", "the chief executive requests you send money urgently and keep this transaction confidential"),
 ("payment", "please transfer funds to the updated bank account instead of the previous beneficiary"),
 ("payment", "purchase gift cards immediately and send the codes privately to the manager"),
]
def normalize(text):
    text=text.lower()
    for old,new in {"passcode":"verification code","pass word":"password","restricted":"suspended","blocked":"disabled","credentials":"login details","ceo":"chief executive","remit":"transfer","wire":"transfer","as soon as possible":"urgently","straight away":"immediately","right away":"immediately"}.items():
        text=re.sub(r"\b"+re.escape(old)+r"\b",new,text)
    return text
@lru_cache(maxsize=1)
def model():
    vectorizer=TfidfVectorizer(analyzer="char_wb",ngram_range=(3,5),sublinear_tf=True)
    matrix=vectorizer.fit_transform([normalize(text) for _,text in EXAMPLES])
    return vectorizer,matrix
def inspect_phrases(text):
    vectorizer,matrix=model(); findings=[]
    sentences=[s.strip() for s in re.split(r"[.!?\n]+",text[:100000]) if 25<=len(s.strip())<=1000][:150]
    if not sentences:return findings
    scores=cosine_similarity(vectorizer.transform([normalize(s) for s in sentences]),matrix)
    for kind in ("credential","payment"):
        matches=[(float(scores[i,j]),sentences[i],EXAMPLES[j][1]) for i in range(len(sentences)) for j in range(len(EXAMPLES)) if EXAMPLES[j][0]==kind]
        score,sentence,prototype=max(matches)
        normalized=normalize(sentence)
        if re.search(r"\b(?:never|do not|don't)\s+(?:send|share|provide|transfer|give)",normalized):continue
        request=bool(re.search(r"\b(?:confirm|verify|provide|validate|sign in|transfer|send|purchase)\b",normalized))
        target=bool(re.search(r"\b(?:password|verification code|login details|account|identity)\b" if kind=="credential" else r"\b(?:money|funds|bank|gift cards|transaction)\b",normalized))
        if score>=0.60 and request and target:
            findings.append(Finding(category="Text" if kind=="credential" else "BEC",rule="phrase_similarity_"+kind,severity="high",confidence=round(min(.9,score),3),title="Threat-like request resembles curated attack phrases",description="A request in the readable email body resembles a credential-loss threat or fraudulent payment instruction.",evidence={"matched_sentence":IndiaPrivacyPreserver.redact_text(sentence[:500]),"reference_phrase":prototype,"similarity":round(score,4),"method":"character TF-IDF cosine similarity"},limitations=["Curated phrase similarity is not a language-model understanding guarantee; novel wording and multilingual phrases require separate evaluation."]))
    return findings

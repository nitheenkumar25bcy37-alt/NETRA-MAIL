"""Small, auditable confusable skeleton; IDN use alone is not malicious."""
import unicodedata
CONFUSABLES = dict(zip("\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u04cf\u03b1\u03bf\u03c1", "aeopcxyijl aop".replace(" ", "")))
def inspect_hostname(hostname, brands):
    labels=[]
    for label in hostname.lower().rstrip(".").split("."):
        try: label=label.encode("ascii").decode("idna") if label.startswith("xn--") else label
        except (UnicodeError,ValueError): pass
        labels.append(label)
    decoded=".".join(labels)
    skeleton="".join(CONFUSABLES.get(c,c) for c in unicodedata.normalize("NFKC",decoded))
    matched=[brand for brand in brands if brand.lower() in skeleton and brand.lower() not in decoded]
    return {"decoded":decoded,"skeleton":skeleton,"lookalike":bool(matched),"matched_brands":matched,"limitations":["Limited curated character coverage; this is a lookalike signal, not ownership proof."]}

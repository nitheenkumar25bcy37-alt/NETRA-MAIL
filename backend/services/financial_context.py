"""Conservative clause-level context for English lexical rules, not a trust list."""
import re

SENTENCES = r'[.!?\n;।]+|\b(?:but|however|instead|then)\b'
ACTION = re.compile(r'\b(?:send|submit|enter|provide|verify|confirm|transfer|wire|pay|remit|purchase|sign in|log in|disclose|share)\b|सत्यापित|भेजें|दर्ज करें|जमा करें|साझा करें|சரிபார்க்க|அனுப்ப|ధృవీకరించ|పంపండి|ಪರಿಶೀಲಿಸ|ಕಳುಹಿಸ|സ്ഥിരീകരിക്ക|അയയ്ക്ക|bhejo|satyaapit|anuppu|saripaar', re.I)
EN_TARGET = re.compile(r'\b(?:password|otp|code|credentials|identity|account|funds|money|payment|gift cards?)\b', re.I)


def passages(text):
    return [s.strip()[:1200] for s in re.split(SENTENCES, text[:100000], flags=re.I) if s.strip()][:250]


def contains_cue(sentence, cue):
    return bool(re.search(r'(?<!\w)' + re.escape(cue) + r'(?!\w)', sentence, re.I)) if cue.isascii() else cue.casefold() in sentence.casefold()


def request_evidence(text, categories):
    """Require a request and sensitive target in one bounded passage."""
    result = []
    for sentence in passages(text):
        # Negative advice remains useful evidence, but not a positive request.
        if re.search(r"\b(?:never|do not|don't)\b|कभी.*(?:न करें|नहीं)|मत\s|வேண்டாம்|వద్దు|ಬೇಡಿ|അരുത്", sentence, re.I):
            # Contrasting clauses are split by passages(); other ambiguous
            # advice is not used as positive language evidence.
            continue
        if not ACTION.search(sentence):
            continue
        matched = {k: [str(c) for c in values if contains_cue(sentence, str(c))] for k, values in categories.items()}
        if not (EN_TARGET.search(sentence) or matched.get('credential_harvesting') or matched.get('financial_fraud')):
            continue
        result.append({'passage': sentence, 'categories': matched})
    return result


def request_text(text):
    """Exclude explicit safety advice and local-document instructions only.

    Keep the original text for ML, forensic evidence, URLs and other checks.
    Split contrasting clauses so advice cannot conceal a subsequent request.
    """
    kept, observations = [], []
    document_window = 0
    for clause in passages(text):
        clause = clause.strip()
        if not clause:
            continue
        if re.fullmatch(r'\d+', clause):
            continue  # Numbered list markers do not consume document context.
        safety = re.fullmatch(r"(?:[\w ]{0,60}\s)?(?:never|do not|don't)\s+(?:share|send|provide|give)\b[^.!?]{0,180}", clause, re.I)
        local = re.fullmatch(r'(?:please\s+)?(?:use|enter)\s+your\s+PAN\b[^.!?]{0,100}\b(?:open|view|unlock)\b[^.!?]{0,40}\b(?:PDF|attachment|statement|document)\b', clause, re.I)
        no_action = re.fullmatch(r'no action is required', clause, re.I)
        if re.search(r'\b(?:open|view|unlock)\b.{0,80}\b(?:attachment|PDF|statement|document)\b', clause, re.I):
            document_window = 4
        else:
            document_window = max(0, document_window - 1)
        contextual_local = document_window and re.fullmatch(r'(?:\d+\s*)?(?:you will be prompted to enter a password|the password is your PAN in upper case|the password is your PAN number in upper case)', clause, re.I)
        # Do not strip advice clauses that also contain another instruction.
        extra_request = re.search(r'\b(?:and|to)\s+(?:send|submit|enter|provide|transfer|click|verify)\b|https?://', clause, re.I)
        if contextual_local or ((safety or local or no_action) and not extra_request):
            observations.append('Safety advice' if safety else 'Local document instruction' if local or contextual_local else 'No action requested')
        else:
            kept.append(clause)
    return '. '.join(kept), sorted(set(observations))

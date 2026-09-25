"""Conservative clause-level context for English lexical rules, not a trust list."""
import re


def request_text(text):
    """Exclude explicit safety advice and local-document instructions only.

    Keep the original text for ML, forensic evidence, URLs and other checks.
    Split contrasting clauses so advice cannot conceal a subsequent request.
    """
    kept, observations = [], []
    for clause in re.split(r'[.!?\n;]+|\b(?:but|however|instead|then)\b', text[:524288], flags=re.I):
        clause = clause.strip()
        if not clause:
            continue
        safety = re.fullmatch(r"(?:[\w ]{0,60}\s)?(?:never|do not|don't)\s+(?:share|send|provide|give)\b[^.!?]{0,180}", clause, re.I)
        local = re.fullmatch(r'(?:please\s+)?(?:use|enter)\s+your\s+PAN\b[^.!?]{0,100}\b(?:open|view|unlock)\b[^.!?]{0,40}\b(?:PDF|attachment|statement|document)\b', clause, re.I)
        no_action = re.fullmatch(r'no action is required', clause, re.I)
        # Do not strip advice clauses that also contain another instruction.
        extra_request = re.search(r'\b(?:and|to)\s+(?:send|submit|enter|provide|transfer|click|verify)\b|https?://', clause, re.I)
        if (safety or local or no_action) and not extra_request:
            observations.append('Safety advice' if safety else 'Local document instruction' if local else 'No action requested')
        else:
            kept.append(clause)
    return '. '.join(kept), sorted(set(observations))

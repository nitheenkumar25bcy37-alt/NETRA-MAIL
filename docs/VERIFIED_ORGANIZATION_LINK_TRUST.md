# Verified organization link trust

NETRA does not mark a message safe merely because its display name says SBI,
Groww, HDFC, Google or another familiar company. Display names and logos are easy
to copy. A reduction in heuristic URL warnings requires all of the following:

1. Gmail's trusted receiver evidence reports DMARC pass for the visible sender.
2. The actual link is under that authenticated sender's domain, or under another
   domain recorded for the same protected organization.
3. Reputation, homograph, internal-address and attachment checks do not report a
   hard warning. Those checks are never bypassed by organization recognition.

This allows a legitimate company to use a first-party campaign redirect without
the tracking link itself becoming proof of phishing. A link to an unrelated or
lookalike domain remains actionable even when the email is authenticated.

## Indian regulated financial domains

`.bank.in` and `.fin.in` allocate an organization name one level below the zone.
For example, the organization identity in `onlinesbi.sbi.bank.in` is
`sbi.bank.in`, not the shared string `bank.in`. NETRA applies that boundary before
brand and visible-link comparisons.

The Reserve Bank of India states that `.bank.in` is an exclusive banking domain
operated through IDRBT, and SBI's official site identifies
`onlinesbi.sbi.bank.in` as its migrated Internet-banking portal:

- https://www.rbi.org.in/scripts/NotificationUser.aspx?Id=12837
- https://sbi.bank.in/web/personal-banking/digital/internet-banking

## Why Gmail's blue check is not the decision input

The Gmail interface badge is useful to a person, but it is presentation state and
is not trustworthy evidence extracted from the message body. NETRA uses the
original MIME fetched through Gmail OAuth and the receiver's trusted
authentication results. This keeps the decision reproducible in the forensic
report and prevents copied logos or page markup from acting as a whitelist.

## Historical reports

Investigations are immutable forensic snapshots. A report created by an older
analysis version keeps its original score. The dashboard now identifies an older
saved result and tells the user to analyze the email again after deployment.

# Beta data and privacy information

This is practical beta information, not a professionally reviewed legal privacy policy.

DriftBeacon stores submitted public GitHub repository URLs with scan metadata. The worker temporarily clones public repository source for static analysis and deletes the temporary clone after the scan finishes or fails.

Completed report metadata and report files are retained for the configured retention period. Report links are public to anyone with the URL until they expire.

Beta usage counters store a keyed hash of the normalised client source and a date bucket. DriftBeacon does not intentionally store raw IP addresses in the beta usage counter table.

Feedback is stored locally to improve the beta. Email is optional and is only retained when the tester explicitly consents to contact. Feedback is not displayed publicly.

Server logs may contain operational request metadata depending on the host and reverse proxy configuration.

Private repository scanning is not supported in this beta. Do not submit private credentials, tokens or repository URLs that include credentials.

DriftBeacon does not sell beta feedback or scan data.

Contact Rob to request deletion of beta feedback or report data where applicable.

# PhishScope

Turns one employee-reported email into a full phishing incident investigation:
header and Received-chain analysis, SPF/DKIM/DMARC explanations with alignment, URL and attachment analysis,
reputation, simulated message trace and click investigation, risk score with what-if toggles, campaign view,
replayable attack graph and timeline, case management, audit trail, dry-run response actions, global IOC pivot page,
and Markdown incident reports.

## Run
    pip install -r requirements.txt
    python app.py            # http://localhost:5000
    # or: docker build -t phishscope . && docker run -p 5000:5000 phishscope

Click **Run phishing sample** or **Run benign sample**, or upload `samples/phish-sample.eml`.

## Reputation (optional)
Set `VT_API_KEY` for real VirusTotal results. Enterprise mode only queries domains and file hashes
(nothing from the email is submitted). Lab mode also looks up full URLs. Without a key, a clearly labelled
`lab-heuristic` stands in so the demo works offline.

## Lab mode and real data
Message trace and click events are simulated deterministically from the message ID (see `campaign()` in `app.py`).
To go live, replace `campaign()` with a provider that reads Microsoft Graph / Exchange message trace and proxy or
Safe Links click logs, returning the same row shape.

## Safety
Email content is escaped in the UI, URLs are defanged, links are never fetched by the server, and response
actions are dry runs written to the audit log.

## Layout
    app.py            API, parser, scoring, simulator, SQLite storage
    static/index.html single-page UI (no build step)
    samples/          demo .eml

## Scoring rules
- SPF/DKIM/DMARC only score when the email carries authentication headers; otherwise they show "not evaluated" (+0).
- Click and credential evidence only corroborates a message that already scores 30+ on its own indicators.
  The lab simulator only generates clicks for messages that already score 60+ (HIGH); suspicious-but-unconfirmed messages
  (30-59) show no simulated clicks, so their score reflects the message alone.
"# phishscope" 

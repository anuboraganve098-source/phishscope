"""PhishScope - phishing investigation & response platform (Flask + SQLite)."""
import os, re, json, hashlib, random, sqlite3, ipaddress, base64, urllib.request, uuid
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory, Response, g

app = Flask(__name__, static_folder="static")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")
BRANDS = ["microsoft", "office365", "paypal", "google", "amazon", "apple", "docusign", "dhl", "netflix", "linkedin"]
URGENT = ["urgent", "immediately", "suspended", "verify", "password", "expire", "action required", "confirm your", "unusual sign", "within 24"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}
BAD_TLD = {"xyz", "top", "click", "icu", "ru", "tk", "zip", "support"}
BAD_EXT = (".exe", ".js", ".html", ".htm", ".iso", ".lnk", ".docm", ".xlsm", ".scr", ".vbs", ".hta", ".img")
WEIGHTS = dict(spf=15, dkim=15, dmarc=20, replyto=10, spoof=10, lookalike=15, vt=30, mismatch=10,
               urgency=5, attach=20, click=25, creds=30)
now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None); d and d.close()
def init():
    c = sqlite3.connect(DB)
    c.executescript("""create table if not exists cases(id integer primary key autoincrement,title text,severity text,status text,created text,data text);
    create table if not exists notes(id integer primary key autoincrement,case_id int,author text,body text,ts text);
    create table if not exists audit(id integer primary key autoincrement,ts text,actor text,action text,detail text);""")
    c.commit(); c.close()
def audit(action, detail=""):
    db().execute("insert into audit(ts,actor,action,detail) values(?,?,?,?)", (now(), "analyst", action, detail)); db().commit()

def defang(u): return u.replace("http", "hxxp", 1).replace(".", "[.]")
def lev(a, b):
    p = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        c = [i]
        for j, cb in enumerate(b, 1): c.append(min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (ca != cb)))
        p = c
    return p[-1]
def lookalike(dom):
    parts = dom.split("."); reg = parts[-2] if len(parts) > 1 else dom
    norm = reg.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w").replace("5", "s")
    for b in BRANDS:
        if reg == b: return None
        if b in norm or lev(norm, b) <= 2 and len(norm) > 4: return b
        if b in dom and reg != b: return b
    return None

class LP(HTMLParser):
    def __init__(s): super().__init__(); s.links = []; s.h = None; s.t = ""
    def handle_starttag(s, t, a):
        if t == "a": s.h = dict(a).get("href"); s.t = ""
    def handle_data(s, d):
        if s.h is not None: s.t += d
    def handle_endtag(s, t):
        if t == "a" and s.h is not None: s.links.append((s.h, s.t.strip())); s.h = None

def rep(kind, value, mode):
    key = os.environ.get("VT_API_KEY")
    if key:  # enterprise: domain/hash lookups only; lab: full URL lookups too
        try:
            if kind == "url" and mode == "lab": ep = "urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            elif kind == "hash": ep = "files/" + value
            else: ep = "domains/" + (urlparse(value).hostname or value if kind == "url" else value)
            r = urllib.request.Request("https://www.virustotal.com/api/v3/" + ep, headers={"x-apikey": key})
            s = json.load(urllib.request.urlopen(r, timeout=8))["data"]["attributes"]["last_analysis_stats"]
            return dict(malicious=s["malicious"], suspicious=s["suspicious"], harmless=s["harmless"] + s["undetected"], source="virustotal")
        except Exception: pass
    host = (urlparse(value).hostname or value) if kind == "url" else value
    pts = (bool(lookalike(host or "")) * 2 + (host.split(".")[-1] in BAD_TLD) + (host in SHORTENERS) + (host.count("-") >= 2)
           + bool(re.fullmatch(r"[\d.]+", host or "")) * 2) if kind != "hash" else 0
    return dict(malicious=8 if pts >= 2 else 0, suspicious=3 if pts >= 1 else 0, harmless=70, source="lab-heuristic")

def analyze(raw, mode):
    m = BytesParser(policy=policy.default).parsebytes(raw)
    fname, faddr = parseaddr(str(m.get("From", ""))); fdom = faddr.split("@")[-1].lower()
    rp = parseaddr(str(m.get("Return-Path", "")))[1]; rpdom = rp.split("@")[-1].lower() if rp else fdom
    rt = parseaddr(str(m.get("Reply-To", "")))[1]
    ar = " ".join(str(x) for x in m.get_all("Authentication-Results", []))
    def res(k):
        x = re.search(rf"\b{k}=(\w+)", ar, re.I); return x.group(1).lower() if x else "none"
    spf, dkim, dmarc = res("spf"), res("dkim"), res("dmarc")
    if spf == "none":
        x = re.match(r"\s*(\w+)", str(m.get("Received-SPF", ""))); spf = x.group(1).lower() if x else "none"
    dd = re.search(r"header\.d=([\w.\-]+)", ar) or re.search(r"\bd=([\w.\-]+)", str(m.get("DKIM-Signature", "")))
    ddom = dd.group(1).lower() if dd else ""
    al = lambda a, b: bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))
    spf_al, dkim_al = spf == "pass" and al(rpdom, fdom), dkim == "pass" and al(ddom, fdom)
    why = []
    why.append(f"SPF {spf.upper()}: envelope sender domain '{rpdom}' " + ("is authorised to send from the connecting IP." if spf == "pass" else "did not authorise the sending IP." if spf != "none" else "published no SPF verdict."))
    why.append(f"DKIM {dkim.upper()}: " + (f"signed by '{ddom}'." if ddom else "no signature found."))
    why.append(f"DMARC {dmarc.upper()}: " + ("SPF or DKIM aligned with the visible From domain." if spf_al or dkim_al else f"neither SPF ({rpdom or '-'}) nor DKIM ({ddom or '-'}) aligned with the visible From domain '{fdom}'."))
    hops, prev = [], None
    for h in reversed([str(x) for x in m.get_all("Received", [])]):
        ips = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", h); fm = re.search(r"from\s+(\S+)", h); by = re.search(r"by\s+(\S+)", h)
        ts = None
        try: ts = datetime.strptime(" ".join(h.split(";")[-1].split()[1:5]), "%d %b %Y %H:%M:%S")
        except Exception: pass
        ip = ips[0] if ips else ""; flags = []
        try:
            if ip and not ipaddress.ip_address(ip).is_private: flags.append("public IP")
            elif ip: flags.append("private IP")
        except ValueError: pass
        if prev and ts and ts < prev: flags.append("timestamp goes backwards")
        prev = ts or prev
        hops.append(dict(frm=fm.group(1) if fm else "?", by=by.group(1) if by else "?", ip=ip, time=ts.isoformat() if ts else "", flags=flags))
    urls, texts, atts, html_body = [], [], [], ""
    for p in m.walk():
        ct, fn = p.get_content_type(), p.get_filename()
        if fn:
            data = p.get_payload(decode=True) or b""
            atts.append(dict(name=fn, size=len(data), sha256=hashlib.sha256(data).hexdigest(), risky=fn.lower().endswith(BAD_EXT)))
        elif ct == "text/html":
            html_body = p.get_content(); lp = LP(); lp.feed(html_body)
            for h, t in lp.links:
                th = urlparse(t if t.startswith("http") else "//" + t).hostname if re.match(r"(https?://)?[\w.-]+\.[a-z]{2,}", t) else None
                urls.append(dict(url=h, text=t, mismatch=bool(th and th != urlparse(h).hostname)))
        elif ct == "text/plain": texts.append(p.get_content())
    body = "\n".join(texts) or re.sub(r"<[^>]+>", " ", html_body)
    seen = {u["url"] for u in urls}
    for u in re.findall(r"https?://[^\s<>\"']+", body):
        if u not in seen: urls.append(dict(url=u, text="", mismatch=False)); seen.add(u)
    for u in urls:
        u["host"] = urlparse(u["url"]).hostname or ""; u["defanged"] = defang(u["url"]); u["lookalike"] = lookalike(u["host"])
        u["rep"] = rep("url", u["url"], mode); u["shortener"] = u["host"] in SHORTENERS
    for a in atts: a["rep"] = rep("hash", a["sha256"], mode)
    return dict(
        meta=dict(subject=str(m.get("Subject", "")), date=str(m.get("Date", "")), message_id=str(m.get("Message-ID", "")), to=str(m.get("To", ""))),
        identity=dict(from_name=fname, from_addr=faddr, from_domain=fdom, return_path=rp, reply_to=rt,
                      replyto_mismatch=bool(rt and rt.split("@")[-1].lower() != fdom),
                      spoof=bool(fname and "@" in fname and fname.lower() != faddr.lower()) or bool(re.search(r"\b(ceo|cfo|it support|helpdesk|security|admin)\b", fname, re.I) and not fdom.endswith("company.com")),
                      lookalike=lookalike(fdom)),
        auth=dict(evaluated=bool(ar.strip() or m.get("Received-SPF")), spf=spf, dkim=dkim, dmarc=dmarc, spf_domain=rpdom, dkim_domain=ddom, spf_aligned=spf_al, dkim_aligned=dkim_al, why=why),
        hops=hops, urls=urls, attachments=atts, preview=body[:3000],
        urgency=[w for w in URGENT if w in (body + str(m.get("Subject", ""))).lower()],
        seed=int(hashlib.md5(str(m.get("Message-ID", raw[:200])).encode()).hexdigest()[:8], 16))

FN = "Alice Bob John Sarah Priya Ravi Meera Arjun Neha Karan Divya Rohan Isha Vikram Anita Sameer Pooja Dev Kavya Nikhil".split()
def campaign(seed, n, p=.15):
    r = random.Random(seed); rows = []
    for i in range(n):
        nm = r.choice(FN); blocked = r.random() < .04; d = r.randint(1, 200)
        row = dict(email=f"{nm.lower()}{i}@company.com", name=nm, dept=r.choice(["Finance", "HR", "Engineering", "Sales", "Support", "Legal", "IT"]),
                   status="blocked" if blocked else "delivered", delivered_at=d, clicked=False, submitted=False)
        if not blocked and r.random() < p:
            ct = d + r.randint(20, 2400)
            row.update(clicked=True, click_at=ct, http=200 if r.random() < .9 else 403, ip=f"10.20.{r.randint(1, 9)}.{r.randint(2, 250)}",
                       ua=r.choice(["Chrome 129 / Windows", "Edge 129 / Windows", "Safari 18 / iOS", "Chrome 129 / Android"]))
            if row["http"] == 200 and r.random() < .3: row.update(submitted=True, submit_at=ct + r.randint(15, 90))
        row["risk"] = "high" if row["submitted"] else "medium" if row["clicked"] else "low"
        rows.append(row)
    return sorted(rows, key=lambda x: x["delivered_at"])

def level(s): return "CRITICAL" if s >= 80 else "HIGH" if s >= 60 else "MEDIUM" if s >= 30 else "LOW"
def finish(a):
    rows = a["campaign"]; clicks = sum(r["clicked"] for r in rows); subs = sum(r["submitted"] for r in rows)
    au, idt = a["auth"], a["identity"]; bad = [u for u in a["urls"] if u["rep"]["malicious"] >= 3]
    ev = au["evaluated"]; ne = "not evaluated (no authentication headers)"
    S = [("spf", "SPF did not pass", ev and au["spf"] != "pass", f"spf={au['spf']}" if ev else ne), ("dkim", "DKIM did not pass", ev and au["dkim"] != "pass", f"dkim={au['dkim']}" if ev else ne),
         ("dmarc", "DMARC did not pass", ev and au["dmarc"] != "pass", f"dmarc={au['dmarc']}" if ev else ne), ("replyto", "Reply-To differs from From", idt["replyto_mismatch"], idt["reply_to"]),
         ("spoof", "Display-name spoofing", idt["spoof"], idt["from_name"]), ("lookalike", "Lookalike sender/URL domain", bool(idt["lookalike"] or any(u["lookalike"] for u in a["urls"])), idt["lookalike"] or "URL host"),
         ("vt", "Malicious URL reputation", bool(bad), ", ".join(u["host"] for u in bad)), ("mismatch", "Link text differs from destination", any(u["mismatch"] for u in a["urls"]), "href mismatch"),
         ("urgency", "Urgent / credential language", bool(a["urgency"]), ", ".join(a["urgency"])), ("attach", "Risky attachment type", any(x["risky"] for x in a["attachments"]), ", ".join(x["name"] for x in a["attachments"] if x["risky"]))]
    base = sum(WEIGHTS[k] for k, _, f, _ in S if f)  # score from the message itself
    corr = base >= 30  # click data only corroborates a message that already looks malicious
    S += [("click", "Users clicked the link", corr and clicks > 0, f"{clicks} clicks" if corr else "not scored: message has no malicious indicators"),
          ("creds", "Credential page loaded after click", corr and subs > 0, f"{subs} likely submissions" if corr else "not scored: message has no malicious indicators")]
    a["signals"] = [dict(id=f"E{i+1}", key=k, label=l, fired=bool(f), evidence=e, weight=WEIGHTS[k]) for i, (k, l, f, e) in enumerate(S)]
    a["score"] = min(100, sum(s["weight"] for s in a["signals"] if s["fired"])); a["level"] = level(a["score"])
    a["verdict"] = "Likely phishing" if a["score"] >= 60 else "Suspicious - analyst review" if a["score"] >= 30 else "Likely benign"
    f = {s["key"]: s for s in a["signals"]}; sm = []
    sm.append(dict(t=f"The message claims {idt['from_domain']} but " + ("failed DMARC" if f["dmarc"]["fired"] else "passed DMARC") + ".", ev=[f["dmarc"]["id"], f["spf"]["id"], f["dkim"]["id"]]))
    if f["vt"]["fired"] or f["lookalike"]["fired"]: sm.append(dict(t=f"Embedded infrastructure looks hostile ({f['vt']['evidence'] or f['lookalike']['evidence']}).", ev=[f["vt"]["id"], f["lookalike"]["id"]]))
    n = len(rows); sm.append(dict(t=f"Campaign reached {sum(r['status']=='delivered' for r in rows)} of {n} recipients; {clicks} clicked and {subs} likely submitted credentials.", ev=[f["click"]["id"], f["creds"]["id"]]))
    a["summary"] = sm
    a["recommended"] = ["Purge delivered copies from all mailboxes", "Block sender and URL domains at gateway/proxy", "Reset credentials and revoke sessions for users who submitted", "Review sign-in logs for clicked users", "Notify the reporting employee"]
    return a

def new_case(raw, n, mode):
    a = analyze(raw, mode); a["mode"] = mode; a["base_time"] = now(); a["campaign"] = []; finish(a); a["campaign"] = campaign(a["seed"], n, .15 if a["score"] >= 60 else 0); finish(a)
    cur = db().execute("insert into cases(title,severity,status,created,data) values(?,?,?,?,?)",
                       (a["meta"]["subject"] or "(no subject)", a["level"], "NEW", now(), json.dumps(a))); db().commit()
    audit("case_created", f"case {cur.lastrowid}"); return cur.lastrowid

def sample_eml():
    m = EmailMessage(); tag = uuid.uuid4().hex[:6]
    m["From"] = '"Microsoft 365 Security" <security@micros0ft-365-support.com>'; m["To"] = "employee@company.com"
    m["Subject"] = "Urgent: Microsoft 365 password expires within 24 hours"; m["Date"] = "Sun, 04 Oct 2026 09:12:03 +0000"
    m["Message-ID"] = f"<{tag}@mailer.micros0ft-365-support.com>"; m["Reply-To"] = "helpdesk@free-mail-box.top"; m["Return-Path"] = "<bounce@mailer.micros0ft-365-support.com>"
    m["Received"] = "from mx.company.com (mx.company.com [10.20.4.15]) by mailbox.company.com with ESMTPS; Sun, 04 Oct 2026 09:12:30 +0000"
    m["Received"] = "from relay.bulkprovider.net (relay.bulkprovider.net [198.51.100.7]) by mx.company.com with ESMTP; Sun, 04 Oct 2026 09:12:20 +0000"
    m["Received"] = "from mailer.micros0ft-365-support.com (unknown [203.0.113.55]) by relay.bulkprovider.net with ESMTP; Sun, 04 Oct 2026 09:12:08 +0000"
    m["Authentication-Results"] = "mx.company.com; spf=fail smtp.mailfrom=mailer.micros0ft-365-support.com; dkim=none; dmarc=fail header.from=micros0ft-365-support.com"
    m.set_content("Your password expires within 24 hours. Verify now: https://micros0ft-365-support.com/login?u=employee")
    m.add_alternative('<p>Your Microsoft 365 password <b>expires within 24 hours</b>.</p><p><a href="https://micros0ft-365-support.com/login?u=employee">https://login.microsoft.com/reset</a></p>', subtype="html")
    m.add_attachment(b"<html><form action='http://203.0.113.55/p'></form></html>", maintype="text", subtype="html", filename="Invoice_4471.html")
    return m.as_bytes()

def benign_eml():
    m = EmailMessage(); m["From"] = "Priya Nair <priya.nair@company.com>"; m["To"] = "team@company.com"; m["Subject"] = "Team meeting moved to 3 pm"
    m["Date"] = "Sun, 04 Oct 2026 08:30:00 +0000"; m["Message-ID"] = f"<{uuid.uuid4().hex[:8]}@company.com>"
    m["Received"] = "from mail.company.com (mail.company.com [10.20.4.15]) by mailbox.company.com with ESMTPS; Sun, 04 Oct 2026 08:30:05 +0000"
    m["Authentication-Results"] = "mx.company.com; spf=pass smtp.mailfrom=company.com; dkim=pass header.d=company.com; dmarc=pass header.from=company.com"
    m.set_content("Hi all, today's sync moves to 3 pm in Room 4. Agenda: https://company.com/wiki/sync"); return m.as_bytes()
@app.route("/")
def index(): return send_from_directory("static", "index.html")
@app.post("/api/analyze")
def api_analyze():
    raw = request.files["file"].read() if "file" in request.files else (request.form.get("text") or "").encode()
    if len(raw) < 20: return jsonify(error="Upload an .eml file or paste raw headers"), 400
    return jsonify(id=new_case(raw, min(int(request.form.get("n", 100)), 500), request.form.get("mode", "enterprise")))
@app.post("/api/lab/sample")
def api_sample(): return jsonify(id=new_case(benign_eml() if request.args.get("kind") == "benign" else sample_eml(), 100, "lab"))
@app.get("/api/lab/sample.eml")
def api_sample_eml(): return Response(sample_eml(), mimetype="message/rfc822", headers={"Content-Disposition": "attachment; filename=phish-sample.eml"})
@app.get("/api/cases")
def api_cases(): return jsonify([dict(r) for r in db().execute("select id,title,severity,status,created from cases order by id desc")])
def load(i):
    r = db().execute("select * from cases where id=?", (i,)).fetchone(); return r, json.loads(r["data"]) if r else None
@app.get("/api/case/<int:i>")
def api_case(i):
    r, d = load(i)
    if not r: return jsonify(error="not found"), 404
    notes = [dict(x) for x in db().execute("select author,body,ts from notes where case_id=? order by id", (i,))]
    acts = [dict(x) for x in db().execute("select ts,action,detail from audit where detail like ? order by id", (f"case {i}%",))]
    return jsonify(id=i, title=r["title"], severity=r["severity"], status=r["status"], created=r["created"], data=d, notes=notes, audit=acts)
@app.post("/api/case/<int:i>/status")
def api_status(i):
    s = request.json["status"]
    if s not in ("NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE POSITIVE"): return jsonify(error="bad status"), 400
    db().execute("update cases set status=? where id=?", (s, i)); db().commit(); audit("status", f"case {i} -> {s}"); return jsonify(ok=1)
@app.post("/api/case/<int:i>/note")
def api_note(i):
    db().execute("insert into notes(case_id,author,body,ts) values(?,?,?,?)", (i, "analyst", request.json["body"][:2000], now())); db().commit(); return jsonify(ok=1)
@app.post("/api/case/<int:i>/action")
def api_action(i):  # dry-run response actions: nothing leaves the lab, everything is audited
    r, d = load(i); act = request.json["action"]; users = [x["email"] for x in d["campaign"] if x["submitted"]] if "Reset" in act else [x["email"] for x in d["campaign"] if x["status"] == "delivered"]
    audit("dry_run_action", f"case {i}: {act} ({len(users)} targets)"); return jsonify(ok=1, targets=len(users), note="Dry run only - no systems were changed.")
@app.get("/api/iocs")
def api_iocs():
    out = {}
    for r in db().execute("select id,created,data from cases"):
        d = json.loads(r["data"]); rc, ck = len(d["campaign"]), sum(x["clicked"] for x in d["campaign"])
        vals = [("domain", d["identity"]["from_domain"], None), ("email", d["identity"]["from_addr"], None), ("message-id", d["meta"]["message_id"], None)]
        vals += [("url", u["defanged"], u["rep"]) for u in d["urls"]] + [("domain", u["host"], u["rep"]) for u in d["urls"]] + [("sha256", a["sha256"], a["rep"]) for a in d["attachments"]]
        vals += [("ip", h["ip"], None) for h in d["hops"] if h["ip"]]
        for t, v, rp in vals:
            o = out.setdefault((t, v), dict(type=t, value=v, cases=set(), recipients=0, clicks=0, rep=rp, first_seen=r["created"]))
            if r["id"] not in o["cases"]: o["cases"].add(r["id"]); o["recipients"] += rc; o["clicks"] += ck
    return jsonify([{**o, "cases": sorted(o["cases"])} for o in out.values()])
@app.get("/api/case/<int:i>/report.md")
def api_report(i):
    r, d = load(i); au, A = d["auth"], d["campaign"]
    md = [f"# Incident INC-{i:04d}: {r['title']}", f"Severity **{d['level']}** ({d['score']}/100 investigation risk score) - Status **{r['status']}**", f"Verdict: **{d['verdict']}**", "", "## Summary"]
    md += [f"- {s['t']} [{', '.join(s['ev'])}]" for s in d["summary"]] + ["", "## Authentication", *[f"- {w}" for w in au["why"]], "", "## Evidence"]
    md += [f"- {s['id']} {'FIRED' if s['fired'] else 'clear'}: {s['label']} (+{s['weight']}) {s['evidence']}" for s in d["signals"]]
    md += ["", "## Campaign", f"Recipients {len(A)}, clicked {sum(x['clicked'] for x in A)}, likely credential submissions {sum(x['submitted'] for x in A)}", "", "### High-risk users"]
    md += [f"- {x['email']} ({x['dept']})" for x in A if x["risk"] == "high"] + ["", "## Indicators"] + [f"- {u['defanged']}" for u in d["urls"]] + [f"- sha256 {a['sha256']}" for a in d["attachments"]]
    md += ["", "## Notes"] + [f"- {n['ts']}: {n['body']}" for n in db().execute("select ts,body from notes where case_id=?", (i,))]
    return Response("\n".join(md), mimetype="text/markdown", headers={"Content-Disposition": f"attachment; filename=INC-{i:04d}.md"})
@app.get("/api/dashboard")
def api_dash():
    rows = [dict(r) for r in db().execute("select id,severity,status,data from cases")]; ck = 0
    for r in rows: ck += sum(x["clicked"] for x in json.loads(r.pop("data"))["campaign"])
    return jsonify(open=sum(r["status"] in ("NEW", "INVESTIGATING") for r in rows), high=sum(r["severity"] in ("HIGH", "CRITICAL") for r in rows), campaigns=len(rows), clicks=ck)

init()
if __name__ == "__main__": app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

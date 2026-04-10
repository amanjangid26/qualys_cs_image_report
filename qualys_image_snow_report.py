#!/usr/bin/env python3
"""
Qualys Container Security - Image SNOW Vulnerability Report  v3.1.0

Fetches container images from the Qualys CSAPI SNOW endpoint, enriches
each QID with title/CVEs/patch status from a per-image vuln API call
(multi-threaded), classifies each QID layer origin, and produces
CSV + JSON reports.

API Endpoints:
  1. POST /auth                              -> JWT token
  2. GET  /images/snow?filter=<QQL>&limit=250 -> all images (paginated)
  3. GET  /images/<SHA>/vuln?type=ALL         -> vuln details (multi-threaded)

QID Layer Classification (3 values):
  isBaseLayer = true  -> "Base"
  isBaseLayer = false -> "Application/Child"
  isBaseLayer = null  -> "null"

Usage:
  export QUALYS_USERNAME="user" QUALYS_PASSWORD="pass"
  python3 qualys_image_snow_report.py -g https://gateway.qg2.apps.qualys.com
  python3 qualys_image_snow_report.py -g ... -d 30
  python3 qualys_image_snow_report.py -g ... -f "vulnerabilities.severity:5"
  python3 qualys_image_snow_report.py -g ... --raw-filter "imagesInUse:`[now-30d ... now]`"

QQL Reference: https://docs.qualys.com/en/cs/1.42.0/search_tips/search_ui_images.htm
"""

import argparse, atexit, concurrent.futures, csv, hashlib, json, logging
import os, random, signal, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone
from urllib.parse import quote as _urlencode

VERSION = "3.1.0"
_GW  = "https://gateway.qg2.apps.qualys.com"
_API = "v1.3"
_LIM = 250
_DAYS = 1
_RET = 3
_CTO = 15
_RTO = 120
_CPS = 2
_THR = 5  # threads for vuln API enrichment

# ── Signal handling ──────────────────────────────────────────────────────
_stop = False
def _onsig(n, _):
    global _stop
    print(f"\n[!] {signal.Signals(n).name} - saving...", file=sys.stderr)
    _stop = True
signal.signal(signal.SIGINT, _onsig)
signal.signal(signal.SIGTERM, _onsig)
def _chk():
    if _stop: raise SystemExit(130)

# ── Utilities ────────────────────────────────────────────────────────────
def _s(v):
    return "" if v is None or v == "None" else str(v)

def _ts(ms):
    if not ms or str(ms) == "0": return ""
    try: return datetime.fromtimestamp(int(ms)/1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except: return str(ms)

def _aj(path, data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f: json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
    except:
        try: os.remove(tmp)
        except: pass
        raise

def _rm(p):
    try: os.remove(p)
    except: pass

def _dur(s):
    s = int(s)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m{s%60}s"
    return f"{s//3600}h{(s%3600)//60}m"

def _sev(sc):
    if sc is None: return ""
    sc = int(sc)
    if sc >= 70: return "CRITICAL"
    if sc >= 40: return "HIGH"
    if sc >= 25: return "MEDIUM"
    return "LOW"

def _fp(a):
    return hashlib.sha256(f"{a.gateway}|{a.days}|{a.limit}|{a.filter or ''}|{a.raw_filter or ''}".encode()).hexdigest()[:16]

def _enc(qql):
    """URL-encode QQL. safe='' encodes ALL special chars (backticks, quotes, colons, brackets, etc.)."""
    return _urlencode(qql, safe='')

# ── Logging ──────────────────────────────────────────────────────────────
def _mklog(od, verbose, quiet):
    lg = logging.getLogger("qsnow"); lg.setLevel(logging.DEBUG); lg.handlers.clear()
    lf = os.path.join(od, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    fh = logging.FileHandler(lf); fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s")); lg.addHandler(fh)
    if not quiet:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG if verbose else logging.INFO)
        ch.setFormatter(logging.Formatter("%(message)s")); lg.addHandler(ch)
    return lg, lf

# ── Lock + Checkpoint ────────────────────────────────────────────────────
def _lock(od, force):
    lp = os.path.join(od, ".lock")
    if os.path.exists(lp):
        try:
            pid = int(open(lp).read().strip()); os.kill(pid, 0)
            if not force: print(f"ERROR: PID {pid} running. --force to override.", file=sys.stderr); sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError): pass
    open(lp, "w").write(str(os.getpid())); atexit.register(lambda: _rm(lp))

class _Ck:
    def __init__(self, d, fp):
        self.p = os.path.join(d, ".checkpoint.json"); self.fp = fp; self.st = {}
        if os.path.exists(self.p):
            try:
                self.st = json.load(open(self.p))
                if self.st.get("fp") != fp: self.st = {}
            except: self.st = {}
    def done(self, ph): return self.st.get(ph) is True
    def mark(self, ph): self.st[ph] = True; self.st["fp"] = self.fp; _aj(self.p, self.st)
    def clear(self): _rm(self.p); self.st = {}

# ── JWT Auth ─────────────────────────────────────────────────────────────
def _auth(gw, user, pwd, log):
    url = f"{gw.rstrip('/')}/auth"; log.info(f"  Authenticating as '{user}'...")
    cmd = ["curl","-s","-w","\n%{http_code}","--connect-timeout",str(_CTO),"--max-time","30",
           "-X","POST",url,"-H","Content-Type: application/x-www-form-urlencoded",
           "-d",f"username={_urlencode(user,safe='')}&password={_urlencode(pwd,safe='')}&token=true"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        ln = r.stdout.strip().split("\n"); code = int(ln[-1]) if ln[-1].isdigit() else 0
        body = "\n".join(ln[:-1]).strip()
    except Exception as e: log.error(f"  Auth failed: {e}"); sys.exit(1)
    if code in (200,201) and body and body.startswith("eyJ"):
        log.info(f"  Token: {body[:15]}...{body[-6:]}"); return body
    log.error(f"  Auth failed: HTTP {code}" + (f" - {body[:200]}" if body else "")); sys.exit(1)

# ── Rate Limiter ─────────────────────────────────────────────────────────
class _RL:
    def __init__(self, cps, log):
        self.iv = 1.0/cps; self.log = log; self.lk = threading.Lock()
        self.last = 0.0; self.pause = 0.0; self.throt = 0
    def acquire(self):
        while True:
            _chk()
            with self.lk:
                now = time.time()
                if now < self.pause:
                    w = self.pause - now; self.lk.release(); time.sleep(w); self.lk.acquire(); continue
                if now - self.last < self.iv:
                    w = self.iv - (now - self.last); self.lk.release(); time.sleep(w); self.lk.acquire(); continue
                self.last = time.time(); return
    def hdr(self, hf):
        if not os.path.exists(hf): return
        rem = win = None
        try:
            for l in open(hf):
                lo = l.lower().strip()
                if lo.startswith("x-ratelimit-remaining:"): rem = int(l.split(":",1)[1].strip())
                elif lo.startswith("x-ratelimit-window-sec:"): win = int(l.split(":",1)[1].strip())
        except: return
        with self.lk:
            if rem is not None and rem <= 0:
                p = (win or 60)+5; self.pause = time.time()+p
                self.log.warning(f"  Rate limit exhausted - pause {p}s"); self.throt += 1
            elif rem is not None and rem <= 20: self.iv = max(self.iv, 1.0)
    def on429(self, hf):
        ra = None
        if os.path.exists(hf):
            try:
                for l in open(hf):
                    if l.lower().strip().startswith("retry-after:"): ra = int(l.split(":",1)[1].strip())
            except: pass
        p = ra or 35
        with self.lk: self.pause = time.time()+p; self.log.warning(f"  429 - pause {p}s"); self.throt += 1

# ── API Client ───────────────────────────────────────────────────────────
class _Api:
    def __init__(self, gw, tok, ret, extra, rl, log):
        self.gw = gw.rstrip("/"); self.tok = tok; self.ret = ret
        self.extra = extra; self.rl = rl; self.log = log
        self.calls = 0; self.retries = 0; self.errors = 0; self._lk = threading.Lock()

    def _inc(self, c=0, r=0, e=0):
        with self._lk: self.calls += c; self.retries += r; self.errors += e

    def get(self, url, out):
        for att in range(self.ret + 1):
            _chk()
            if att > 0:
                time.sleep(random.uniform(1, min(15, 2**att))); self._inc(r=1)
            self.rl.acquire()
            hdr = out + ".hdr"
            cmd = ["curl","-s","-o",out,"-D",hdr,"-w","%{http_code}",
                   "--connect-timeout",str(_CTO),"--max-time",str(_RTO),
                   "-X","GET",url,"-H","Accept: application/json",
                   "-H",f"Authorization: Bearer {self.tok}"]
            if self.extra: cmd.extend(self.extra.split())
            try:
                r = subprocess.run(cmd, capture_output=True, text=True)
                code = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
            except: self._inc(c=1, e=1); continue
            self._inc(c=1); self.rl.hdr(hdr)
            if code in (200, 204): _rm(hdr); return code
            if code == 401: self.log.error("HTTP 401 - token expired."); sys.exit(1)
            if code == 403: self.log.error("HTTP 403 - no permission."); sys.exit(1)
            if code == 404: _rm(hdr); return 404
            if code == 429: self.rl.on429(hdr)
            _rm(hdr)
        self._inc(e=1); return 0

    def fetch_snow(self, base_url, pages_dir, limit):
        all_recs = []; seen = set(); pg = 1; off = 0
        while True:
            _chk()
            sep = "&" if "?" in base_url else "?"
            url = f"{base_url}{sep}offset={off}"
            pf = os.path.join(pages_dir, f"snow_{pg:04d}.json")
            if os.path.exists(pf):
                try:
                    d = json.load(open(pf)).get("data", [])
                    if isinstance(d, list) and d:
                        shas = {i.get("sha") for i in d if i.get("sha")}
                        if shas and shas.issubset(seen):
                            self.log.info(f"  page {pg}: duplicate - stopping"); _rm(pf); break
                        all_recs.extend(d); seen.update(shas)
                        self.log.info(f"  page {pg}: {len(d)} (cached, total: {len(all_recs)})")
                        if len(d) < limit: break
                        off += limit; pg += 1; continue
                except: pass
            self.log.info(f"  Fetching page {pg} (offset={off})...")
            code = self.get(url, pf)
            if code == 204: self.log.info(f"  page {pg}: 204 - done"); _rm(pf); break
            if code != 200: self.log.error(f"  Failed page {pg} (HTTP {code})"); break
            try: d = json.load(open(pf)).get("data", [])
            except: break
            if not isinstance(d, list) or not d:
                self.log.info(f"  page {pg}: empty - done"); _rm(pf); break
            shas = {i.get("sha") for i in d if i.get("sha")}
            if shas and shas.issubset(seen):
                self.log.info(f"  page {pg}: duplicate - done"); _rm(pf); break
            all_recs.extend(d); seen.update(shas)
            self.log.info(f"  page {pg}: {len(d)} (total: {len(all_recs)})")
            if len(d) < limit: break
            off += limit; pg += 1
        self.log.info(f"  Total: {len(all_recs)} images, {pg} page(s)")
        return all_recs

# ── Multi-threaded vuln enrichment ───────────────────────────────────────
def _enrich_vulns(api, base_url, pages_dir, vcache_dir, log, threads=_THR):
    """Fetch /images/<SHA>/vuln for each unique SHA using thread pool."""
    unique_shas = set()
    pg = 1
    while True:
        pf = os.path.join(pages_dir, f"snow_{pg:04d}.json")
        if not os.path.exists(pf): break
        try:
            d = json.load(open(pf)).get("data", [])
            if not isinstance(d, list) or not d: break
            for img in d:
                sha = img.get("sha")
                if sha: unique_shas.add(sha)
            pg += 1
        except: break

    # Split into cached vs to-fetch
    to_fetch = []
    global_qid_map = {}
    for sha in unique_shas:
        cf = os.path.join(vcache_dir, f"{sha[:16]}.json")
        if os.path.exists(cf):
            try:
                for qid_str, det in json.load(open(cf)).items():
                    global_qid_map[int(qid_str)] = det
                continue
            except: pass
        to_fetch.append(sha)

    cached_count = len(unique_shas) - len(to_fetch)
    log.info(f"  {len(unique_shas)} images: {cached_count} cached, {len(to_fetch)} to fetch ({threads} threads)")
    if not to_fetch:
        return global_qid_map

    completed = [0]
    total = len(to_fetch)
    t0 = time.time()
    counter_lock = threading.Lock()

    def _fetch_one(sha):
        _chk()
        cf = os.path.join(vcache_dir, f"{sha[:16]}.json")
        vuln_url = f"{base_url}/images/{sha}/vuln?type=ALL&applyException=true"
        tmp = os.path.join(vcache_dir, f"_t_{sha[:12]}_{threading.current_thread().ident}.json")
        qid_map = {}
        code = api.get(vuln_url, tmp)
        if code == 200:
            try:
                for v in json.load(open(tmp)).get("details", []):
                    qid = v.get("qid")
                    if qid is None: continue
                    cves = ", ".join(v.get("cveids") or [])
                    pa = v.get("patchAvailable")
                    qid_map[str(qid)] = {
                        "title": _s(v.get("title")),
                        "cveids": cves,
                        "patchAvailable": "true" if pa is True else ("false" if pa is False else ""),
                    }
            except: pass
        _rm(tmp)
        _aj(cf, qid_map)
        with counter_lock:
            for qid_str, det in qid_map.items():
                global_qid_map[int(qid_str)] = det
            completed[0] += 1
            if completed[0] % 20 == 0 or completed[0] == total:
                elapsed = time.time() - t0
                rate = elapsed / completed[0] if completed[0] else 1
                left = (total - completed[0]) * rate
                log.info(f"  Vuln enrichment: {completed[0]}/{total} ({_dur(left)} left)")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_fetch_one, sha): sha for sha in to_fetch}
        for f in concurrent.futures.as_completed(futures):
            _chk()
            try: f.result()
            except SystemExit: raise
            except: pass

    log.info(f"  Enriched {len(global_qid_map)} QIDs from {len(unique_shas)} images in {_dur(time.time()-t0)}")
    return global_qid_map

# ── Page iterator ────────────────────────────────────────────────────────
def _iter(d):
    pg = 1
    while True:
        pf = os.path.join(d, f"snow_{pg:04d}.json")
        if not os.path.exists(pf): break
        try:
            data = json.load(open(pf)).get("data", [])
            if not isinstance(data, list) or not data: break
            yield from data; pg += 1
        except: break

def _count(d):
    n = 0; pg = 1
    while True:
        pf = os.path.join(d, f"snow_{pg:04d}.json")
        if not os.path.exists(pf): break
        try:
            data = json.load(open(pf)).get("data", [])
            if not isinstance(data, list) or not data: break
            n += len(data); pg += 1
        except: break
    return n

# ── Layer classification ─────────────────────────────────────────────────
def _lmap(img):
    m = {}
    for l in (img.get("layers") or []):
        sha = l.get("sha")
        if sha: m[sha] = (l.get("isBaseLayer"), l.get("createdBy") or "")
    return m

def _classify(vshas, lm):
    """3 values: Base, Application/Child, null. Returns (label, sha, createdBy)."""
    if not vshas: return "", "", ""
    for sha in vshas:
        if sha in lm:
            ib, cb = lm[sha]
            if ib is True: return "Base", sha, cb
            if ib is False: return "Application/Child", sha, cb
            return "null", sha, cb
    return "null", (vshas[0] if vshas else ""), ""

def _repos(img):
    rs = img.get("repo") or []; ds = img.get("repoDigests") or []
    dm = {d["repository"]: d["registry"] for d in ds if d.get("registry") and d.get("repository")}
    result = []
    for r in rs:
        reg = r.get("registry") or ""; rp = _s(r.get("repository"))
        if not reg and rp: reg = dm.get(rp, "")
        result.append({"registry": _s(reg), "repository": rp, "tag": _s(r.get("tag"))})
    return result or [{"registry": "", "repository": "", "tag": ""}]

# ── CSV + JSON (27 columns, 1 row per image×QID) ────────────────────────
HDRS = [
    "Image_ID", "Image_SHA", "Operating_System", "Architecture",
    "Image_Created", "Image_Last_Scanned", "Image_Scan_Types", "Image_Source",
    "Registry", "Repository", "Image_Tag", "Risk_Score",
    "Parent_Base_Image", "Associated_Container_Count", "Total_Vulnerabilities_On_Image",
    "Vuln_QID", "Vuln_Title", "Vuln_QDS_Score", "Vuln_QDS_Severity", "Vuln_Scan_Type",
    "Vuln_CVE_IDs", "Vuln_Patch_Available",
    "QID_Layer_Type", "QID_Layer_SHA", "Docker_Layer_Instruction",
    "Affected_Packages", "Affected_Package_Paths",
]
EV = [""] * 12  # empty vuln+sw cols

def _club_software(software_list):
    """Club multiple software into single pipe-separated values.
    Affected_Packages:     pkg1 (v1 -> v2) | pkg2 (v3 -> v4)
    Affected_Package_Paths: path1 | path2
    """
    packages = []
    paths = []
    seen = set()
    for sw in (software_list or []):
        name = _s(sw.get("name"))
        ver = _s(sw.get("version"))
        fix = _s(sw.get("fixVersion"))
        path = _s(sw.get("packagePath"))
        key = f"{name}|{ver}|{fix}"
        if key in seen: continue
        seen.add(key)
        if name:
            entry = name
            if ver and fix: entry += f" ({ver} -> {fix})"
            elif ver: entry += f" ({ver})"
            packages.append(entry)
        if path: paths.append(path)
    return " | ".join(packages), " | ".join(paths)

def _gen_csv(pages_dir, qid_map, csv_path, log):
    tmp = csv_path + ".tmp"
    total_rows = 0; total_imgs = 0; total_vulns = 0
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(HDRS)
        for img in _iter(pages_dir):
            total_imgs += 1; _chk()
            sha = img.get("sha", "")
            vl = img.get("vulnerabilities") or []
            rps = _repos(img); lm = _lmap(img)
            cc = img.get("associatedContainersCount", 0)
            parent = _s(img.get("baseImage"))
            ib = [_s(img.get("imageId")), sha, _s(img.get("operatingSystem")),
                  _s(img.get("architecture")), _ts(img.get("created")),
                  _ts(img.get("lastScanned")),
                  " | ".join(_s(x) for x in (img.get("scanTypes") or [])),
                  " | ".join(_s(x) for x in (img.get("source") or []))]
            for rp in rps:
                ic = ib + [rp["registry"], rp["repository"], rp["tag"],
                           _s(img.get("riskScore")), parent, str(cc), str(len(vl))]
                if vl:
                    for v in vl:
                        total_vulns += 1
                        qid = v.get("qid"); qds = v.get("qdsScore")
                        enr = qid_map.get(qid, {})
                        o, ls, cb = _classify(v.get("layerSha") or [], lm)
                        pkgs, paths = _club_software(v.get("software") or [])
                        vc = [_s(qid), enr.get("title",""),
                              _s(qds) if qds is not None else "", _sev(qds),
                              " | ".join(_s(x) for x in (v.get("scanType") or [])),
                              enr.get("cveids",""), enr.get("patchAvailable",""),
                              o, ls, cb, pkgs, paths]
                        w.writerow(ic + vc); total_rows += 1
                else:
                    w.writerow(ic + EV); total_rows += 1
    os.replace(tmp, csv_path)
    log.info(f"  CSV: {csv_path} ({total_rows:,} rows x {len(HDRS)} cols)")
    return total_rows, total_imgs, total_vulns

def _gen_json(pages_dir, qid_map, json_path, log):
    tmp = json_path + ".tmp"; ti = tv = 0
    with open(tmp, "w", encoding="utf-8") as f:
        f.write('{\n  "generatedAt": "' + datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + '",\n  "images": [\n')
        first = True
        for img in _iter(pages_dir):
            ti += 1; _chk()
            lm = _lmap(img); vl = img.get("vulnerabilities") or []
            jvulns = []
            for v in vl:
                tv += 1; qid = v.get("qid"); qds = v.get("qdsScore")
                enr = qid_map.get(qid, {})
                o, ls, cb = _classify(v.get("layerSha") or [], lm)
                pkgs, paths = _club_software(v.get("software") or [])
                jvulns.append({"qid":qid,"title":enr.get("title",""),"qdsScore":qds,
                    "qdsSeverity":_sev(qds),"cveIds":enr.get("cveids",""),
                    "patchAvailable":enr.get("patchAvailable",""),
                    "qidLayerType":o,"qidLayerSha":ls,"dockerLayerInstruction":cb,
                    "affectedPackages":pkgs,"affectedPackagePaths":paths})
            rec = {"imageId":_s(img.get("imageId")),"sha":img.get("sha",""),
                "operatingSystem":_s(img.get("operatingSystem")),
                "riskScore":img.get("riskScore"),
                "parentBaseImage":_s(img.get("baseImage")),
                "associatedContainerCount":img.get("associatedContainersCount",0),
                "totalVulnerabilities":len(vl),
                "repositories":_repos(img),"vulnerabilities":jvulns}
            if not first: f.write(',\n')
            f.write('    ' + json.dumps(rec, default=str)); first = False
        f.write(f'\n  ],\n  "totalImages": {ti},\n  "totalVulnerabilities": {tv}\n}}\n')
    os.replace(tmp, json_path); log.info(f"  JSON: {json_path}")

# ── CLI ──────────────────────────────────────────────────────────────────
def _cli():
    p = argparse.ArgumentParser(prog="qualys_image_snow_report",
        description=f"Qualys CS Image SNOW Vulnerability Report v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="QQL tokens: https://docs.qualys.com/en/cs/1.42.0/search_tips/search_ui_images.htm")
    e = os.environ.get
    p.add_argument("-u","--username",default=e("QUALYS_USERNAME",""))
    p.add_argument("-p","--password",default=e("QUALYS_PASSWORD",""))
    p.add_argument("-g","--gateway",default=e("QUALYS_GATEWAY",_GW))
    p.add_argument("-d","--days",type=int,default=int(e("QUALYS_DAYS",_DAYS)))
    p.add_argument("-f","--filter",default=e("QUALYS_FILTER",""))
    p.add_argument("--raw-filter",default=e("QUALYS_RAW_FILTER",""))
    p.add_argument("-l","--limit",type=int,default=int(e("QUALYS_LIMIT",_LIM)))
    p.add_argument("-o","--output-dir",default=e("QUALYS_OUTPUT_DIR","./qualys_snow_output"))
    p.add_argument("--force",action="store_true")
    p.add_argument("--threads",type=int,default=int(e("QUALYS_THREADS",_THR)),help=f"Threads for vuln enrichment (default: {_THR})")
    p.add_argument("-r","--retries",type=int,default=_RET)
    p.add_argument("--cps",type=int,default=int(e("QUALYS_CPS",_CPS)))
    p.add_argument("-C","--curl-extra",default=e("QUALYS_CURL_EXTRA",""))
    p.add_argument("-v","--verbose",action="store_true")
    p.add_argument("-q","--quiet",action="store_true")
    p.add_argument("--dry-run",action="store_true")
    return p.parse_args()

# ── Main ─────────────────────────────────────────────────────────────────
def main():
    a = _cli(); t0 = time.time()
    if not a.username or not a.password:
        print("ERROR: Set QUALYS_USERNAME + QUALYS_PASSWORD or -u/-p.", file=sys.stderr); sys.exit(1)
    if not a.gateway.startswith("https://"):
        print("ERROR: Gateway must use HTTPS.", file=sys.stderr); sys.exit(1)

    if a.raw_filter: qql = a.raw_filter
    else:
        qql = f"imagesInUse:`[now-{a.days}d ... now]`"
        if a.filter: qql += f" and {a.filter}"

    od = a.output_dir; pd = os.path.join(od, "pages"); vd = os.path.join(od, "vuln_cache")
    os.makedirs(pd, exist_ok=True); os.makedirs(vd, exist_ok=True)
    log, lf = _mklog(od, a.verbose, a.quiet); _lock(od, a.force)

    base = f"{a.gateway.rstrip('/')}/csapi/{_API}"
    snow_url = f"{base}/images/snow?filter={_enc(qql)}&limit={a.limit}"

    log.info(f"Qualys Image SNOW Report v{VERSION}")
    log.info(f"  Gateway  : {a.gateway}  |  User: {a.username}")
    log.info(f"  QQL      : {qql}")
    log.info(f"  Limit    : {a.limit}/page  |  Threads: {a.threads}  |  CPS: {a.cps}")
    log.info(f"  Output   : {od}")

    if a.dry_run:
        log.info(f"\n  ** DRY RUN **")
        log.info(f"  SNOW URL : {snow_url}")
        log.info(f"  Vuln URL : {base}/images/<SHA>/vuln?type=ALL&applyException=true"); return

    ck = _Ck(od, _fp(a))
    if ck.done("complete") and not a.force: log.info("\nDone already. --force for fresh."); return
    if a.force: ck.clear()

    log.info(f"\n[Phase 0] Authentication")
    tok = _auth(a.gateway, a.username, a.password, log)
    rl = _RL(a.cps, log)
    api = _Api(a.gateway, tok, a.retries, a.curl_extra, rl, log)

    if ck.done("fetch"):
        log.info(f"\n[Phase 1] Fetch SNOW - cached"); nc = _count(pd)
    else:
        log.info(f"\n[Phase 1] Fetching SNOW images...")
        nc = len(api.fetch_snow(snow_url, pd, a.limit)); ck.mark("fetch")
    if nc == 0: log.warning("  0 images. Check QQL filter.")

    if ck.done("vuln"):
        log.info(f"\n[Phase 2] Vuln enrichment - cached")
        qid_map = {}
        for cf in os.listdir(vd):
            if cf.endswith(".json") and not cf.startswith("_"):
                try:
                    for k, v in json.load(open(os.path.join(vd, cf))).items(): qid_map[int(k)] = v
                except: pass
        log.info(f"  {len(qid_map)} QIDs from cache")
    else:
        log.info(f"\n[Phase 2] Vuln enrichment ({a.threads} threads)...")
        qid_map = _enrich_vulns(api, base, pd, vd, log, a.threads); ck.mark("vuln")

    if ck.done("reports"):
        log.info(f"\n[Phase 3] Reports - cached"); cr = tv = 0
    else:
        log.info(f"\n[Phase 3] Generating reports...")
        cr, _, tv = _gen_csv(pd, qid_map, os.path.join(od, "qualys_image_snow_report.csv"), log)
        _gen_json(pd, qid_map, os.path.join(od, "qualys_image_snow_report.json"), log)
        ck.mark("reports")

    el = time.time() - t0
    log.info(f"\n{'='*60}")
    log.info(f"  REPORT COMPLETE")
    log.info(f"{'='*60}")
    log.info(f"  Duration  : {_dur(el)}")
    log.info(f"  Images    : {nc}  |  QIDs enriched: {len(qid_map)}")
    log.info(f"  CSV       : {cr:,} rows x {len(HDRS)} cols")
    log.info(f"  API calls : {api.calls} (retries: {api.retries}, errors: {api.errors})")
    log.info(f"{'='*60}")

    _aj(os.path.join(od, "run_summary.json"), {
        "version": VERSION, "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "gateway": a.gateway, "qql_filter": qql,
        "total_images": nc, "qids_enriched": len(qid_map),
        "csv_rows": cr, "csv_cols": len(HDRS), "duration": _dur(el),
        "api_calls": api.calls, "threads": a.threads})
    ck.mark("complete")
    log.info(f"\n  Reports -> {od}/")

if __name__ == "__main__": main()

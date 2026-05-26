"""
EMAIL SANITIZATION — BATCH PROCESSOR
For processing Lakhs (100,000+) of emails

HOW TO RUN:
  python batch_processor.py --file your_list.csv --email-col email

OPTIONS:
  --file         Input CSV/Excel file
  --email-col    Column name with emails (default: email)
  --concurrency  Parallel HTTP requests (default: 50)
  --chunk        Save checkpoint every N rows (default: 1000)
  --skip-hibp    Skip HIBP (saves time, run overnight separately)
  --github-token Your GitHub personal access token
  --hibp-key     Your HIBP API key
  --ipqs-key     Your IPQS API key
  --resume       Resume from last checkpoint

EXAMPLE:
  python batch_processor.py --file emails.csv --email-col email --concurrency 50
  python batch_processor.py --file emails.csv --resume  (continue after crash)
"""

import asyncio
import aiohttp
import pandas as pd
import numpy as np
import re
import math
import hashlib
import json
import os
import time
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from tqdm import tqdm
from difflib import SequenceMatcher

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ─────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────
CONFIG = {
    "gravatar_concurrency": 50,   # Parallel gravatar requests
    "github_concurrency":   30,   # Parallel github requests
    "hibp_delay":           1.6,  # Seconds between HIBP calls (their ToS = 1.5)
    "request_timeout":      8,    # Seconds per request
    "chunk_size":           1000, # Save checkpoint every N rows
    "output_dir":           "output",
}

# ─────────────────────────────────────────────────────────────
#  DATASETS (same as before)
# ─────────────────────────────────────────────────────────────
BIG = {
    "gmail.com","googlemail.com","yahoo.com","yahoo.co.uk","yahoo.co.in",
    "yahoo.com.au","yahoo.ca","yahoo.fr","yahoo.de","ymail.com","rocketmail.com",
    "hotmail.com","hotmail.co.uk","hotmail.fr","hotmail.in",
    "outlook.com","outlook.in","outlook.co.uk","live.com","live.co.uk",
    "live.in","msn.com","icloud.com","me.com","mac.com",
    "rediffmail.com","protonmail.com","proton.me","zoho.com",
}
TRAPS = {
    "spamtrap.ro","spamgourmet.com","spamgourmet.net","spamgourmet.org",
    "spamhole.com","spamcop.net","spam.la","spamex.com","spam.su",
    "mailnull.com","deadaddress.com","darkharvestspam.com",
    "trap.email","spamtrap.com","spamtrap.net","spamoff.de",
    "example.com","example.net","example.org","test.com",
    "invalid.com","nowhere.com","devnull.com",
}
DISPOSABLE = {
    "mailinator.com","mailinator.net","yopmail.com","yopmail.fr",
    "tempmail.com","temp-mail.org","temp-mail.io","tempmail.net",
    "tempr.email","10minutemail.com","10minutemail.net","10minutemail.org",
    "guerrillamail.com","guerrillamail.info","guerrillamail.biz",
    "guerrillamail.de","guerrillamail.net","guerrillamail.org",
    "sharklasers.com","grr.la","spam4.me","trashmail.com","trashmail.me",
    "trashmail.net","trashmail.at","trashmail.io","trashmail.xyz",
    "mohmal.com","mytemp.email","discard.email","maildrop.cc",
    "fakeinbox.com","throwam.com","throwaway.email","getairmail.com",
    "mailnesia.com","dispostable.com","filzmail.com",
}
TYPOS = {
    "gmial.com":"gmail.com","gmaill.com":"gmail.com","gmal.com":"gmail.com",
    "gmai.com":"gmail.com","gmali.com":"gmail.com","gmail.co":"gmail.com",
    "gmail.cm":"gmail.com","gmail.cmo":"gmail.com","gmail.con":"gmail.com",
    "gnail.com":"gmail.com","gamil.com":"gmail.com","gmail.ocm":"gmail.com",
    "yaho.com":"yahoo.com","yahooo.com":"yahoo.com","yhoo.com":"yahoo.com",
    "yhaoo.com":"yahoo.com","yahoo.co":"yahoo.com","yahoo.cmo":"yahoo.com",
    "yaoo.com":"yahoo.com","ahoo.com":"yahoo.com","yahoomail.com":"yahoo.com",
    "hotmai.com":"hotmail.com","hotmial.com":"hotmail.com",
    "hotmaill.com":"hotmail.com","hotmal.com":"hotmail.com",
    "hotmali.com":"hotmail.com","hotmail.co":"hotmail.com",
    "hotmail.cm":"hotmail.com","hotmail.cmo":"hotmail.com",
    "homail.com":"hotmail.com","hotmeil.com":"hotmail.com",
    "outlok.com":"outlook.com","outloo.com":"outlook.com",
    "outllok.com":"outlook.com","outlook.co":"outlook.com",
    "otlook.com":"outlook.com","rediff.com":"rediffmail.com",
}
ROLES = {
    "admin","administrator","webmaster","hostmaster","postmaster",
    "info","information","contact","hello","support","help","helpdesk",
    "service","customer","care","sales","marketing","billing","accounts",
    "noreply","no-reply","donotreply","do-not-reply","abuse","spam",
    "security","privacy","hr","jobs","careers","newsletter","news",
    "updates","alerts","root","sys","system","press","media",
    "legal","compliance","team","office","mail",
}
EMAIL_RE = re.compile(
    r"^(?!.*\.\.)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    re.IGNORECASE)
PAT_SUSP = re.compile(
    r"(temp|test|spam|trap|fake|dummy|null|noreply|delete|"
    r"removed|invalid|bounce|dead|block)", re.IGNORECASE)

_mx_cache = {}
def has_mx(domain):
    if domain in BIG: return True
    if domain in _mx_cache: return _mx_cache[domain]
    if not DNS_OK: _mx_cache[domain]=True; return True
    try:
        dns.resolver.resolve(domain,"MX"); _mx_cache[domain]=True; return True
    except:
        try: dns.resolver.resolve(domain,"A"); _mx_cache[domain]=True; return True
        except: _mx_cache[domain]=False; return False


# ─────────────────────────────────────────────────────────────
#  ENTROPY HELPERS
# ─────────────────────────────────────────────────────────────
def calc_entropy(s):
    if not s: return 0.0
    f = {}
    for c in s: f[c] = f.get(c, 0) + 1
    return -sum((v/len(s))*math.log2(v/len(s)) for v in f.values())

def num_density(s):
    return sum(1 for c in s if c.isdigit()) / len(s) if s else 0.0

def vowel_ratio(s):
    L = [c for c in s.lower() if c.isalpha()]
    return sum(1 for c in L if c in "aeiou") / len(L) if L else 0.0

def usernames(local):
    b = local.split("+")[0]
    v = [b.replace(".",""), b, b.replace(".","-")]
    seen = []
    for x in v:
        if x not in seen and len(x) >= 2: seen.append(x)
    return seen[:2]  # Max 2 for speed

def temporal_risk(days):
    if days is None: return 8, "Unknown"
    if days < 90:    return -25, f"Very active ({days}d)"
    elif days < 180: return -15, f"Active ({days}d)"
    elif days < 365: return -5,  f"Somewhat active ({days}d)"
    elif days < 730: return +10, f"Dormant ({days}d)"
    elif days < 1460:return +20, f"Likely abandoned"
    else:            return +30, f"Abandoned ({days//365}yr)"

def days_since(date_str):
    if not date_str: return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z","+00:00"))
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except: return None


# ─────────────────────────────────────────────────────────────
#  PHASE 1: LOCAL VALIDATION (no network — instant)
# ─────────────────────────────────────────────────────────────
def local_validate(email: str) -> dict:
    """
    Runs instantly. No network calls.
    Process all 1 lakh in ~2 minutes.
    """
    email = str(email).strip().lower()

    base = {
        "email": email, "local_score": 0,
        "is_spam_trap": False, "is_disposable": False,
        "is_typo": False, "typo_fix": "", "is_role": False,
        "username_risk": "LOW", "entropy": 0.0,
        "num_density": 0.0, "vowel_ratio": 0.0,
        "is_big_provider": False, "has_mx": True,
        "local_reasons": [], "needs_api": False, "terminal": False,
    }

    if not email or "@" not in email:
        base.update({"local_score":100,"terminal":True,
                     "local_reasons":["Invalid/empty"]})
        return base

    local, domain = email.split("@", 1)

    if not EMAIL_RE.match(email) or len(email)>254 or len(local)>64:
        base.update({"local_score":100,"terminal":True,
                     "local_reasons":["Bad syntax"]})
        return base

    is_big = domain in BIG
    base["is_big_provider"] = is_big
    score = 0

    # Spam trap → terminal
    if domain in TRAPS:
        base.update({"is_spam_trap":True,"terminal":True,"local_score":100,
                     "local_reasons":[f"Spam trap domain: {domain}"]})
        return base
    for td in TRAPS:
        if domain.endswith("."+td):
            base.update({"is_spam_trap":True,"terminal":True,"local_score":100,
                         "local_reasons":[f"Sub-domain of spam trap"]})
            return base

    # Disposable
    if domain in DISPOSABLE:
        base["is_disposable"] = True
        score += 70
        base["local_reasons"].append(f"Disposable: {domain}")

    # Typo (not for big providers)
    if not is_big:
        if domain in TYPOS:
            base["is_typo"] = True
            base["typo_fix"] = TYPOS[domain]
            score += 65
            base["local_reasons"].append(f"Typo: {domain}→{TYPOS[domain]}")
        else:
            for p in BIG:
                sim = SequenceMatcher(None,domain,p).ratio()
                if 0.82 <= sim < 1.0:
                    base["is_typo"]=True; base["typo_fix"]=p
                    score += 55
                    base["local_reasons"].append(f"Typo-like: {domain}≈{p}")
                    break

    # Role
    b = local.split("+")[0]
    if b in ROLES:
        base["is_role"] = True; score += 25
        base["local_reasons"].append(f"Role address: {b}@")

    # Entropy
    clean = local.replace(".","").replace("_","").replace("-","").replace("+","")
    ent = calc_entropy(clean); nd = num_density(clean); vr = vowel_ratio(clean)
    base.update({"entropy":round(ent,3),"num_density":round(nd,3),"vowel_ratio":round(vr,3)})

    es = 0
    if PAT_SUSP.search(local): es+=40; base["local_reasons"].append("Suspicious keyword")
    if ent>=3.5: es+=20; base["local_reasons"].append(f"High randomness {ent:.2f}")
    elif ent>=3.0: es+=10
    if nd>=0.6: es+=20; base["local_reasons"].append(f"{int(nd*100)}% digits")
    elif nd>=0.4: es+=10
    if vr==0 and len(clean)>=4: es+=15; base["local_reasons"].append("No vowels")
    if clean.isdigit(): es+=25; base["local_reasons"].append("Pure numeric")
    if len(local)<=2: es+=20
    if len(local)>30: es+=15
    if es>=40: base["username_risk"]="HIGH"
    elif es>=15: base["username_risk"]="MEDIUM"
    score += es

    # MX (for non-big providers only)
    if not is_big:
        ok = has_mx(domain); base["has_mx"] = ok
        if not ok:
            score += 90; base["local_reasons"].append("No MX record")

    base["local_score"] = min(score, 100)

    # Decide if API checks needed
    # Skip API for clearly bad OR clearly safe
    base["needs_api"] = is_big and (15 <= base["local_score"] <= 85)

    return base


# ─────────────────────────────────────────────────────────────
#  PHASE 2: ASYNC GRAVATAR (50 concurrent = 33 min for 1 lakh)
# ─────────────────────────────────────────────────────────────
async def check_gravatar_async(session, email):
    try:
        h    = hashlib.md5(email.encode()).hexdigest()
        url  = f"https://www.gravatar.com/avatar/{h}?d=404"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
            return {"email":email, "found":resp.status==200,
                    "impact":-15 if resp.status==200 else 0}
    except:
        return {"email":email, "found":False, "impact":0}

async def batch_gravatar(emails, concurrency=50):
    """
    Process gravatar checks for all emails concurrently.
    50 simultaneous connections = ~50x faster than sequential.
    """
    results = {}
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(concurrency)

        async def bounded(email):
            async with sem:
                return await check_gravatar_async(session, email)

        tasks = [bounded(e) for e in emails]
        with tqdm(total=len(tasks), desc="  Gravatar", unit="email",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for coro in asyncio.as_completed(tasks):
                r = await coro
                results[r["email"]] = r
                pbar.update(1)
    return results


# ─────────────────────────────────────────────────────────────
#  PHASE 3: ASYNC GITHUB
# ─────────────────────────────────────────────────────────────
async def check_github_async(session, local, email, token=""):
    headers = {"Accept":"application/vnd.github.v3+json"}
    if token: headers["Authorization"] = f"token {token}"

    for uname in usernames(local):
        try:
            url = f"https://api.github.com/users/{uname}"
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=6)) as resp:
                if resp.status == 200:
                    data     = await resp.json()
                    updated  = data.get("updated_at","")
                    days     = days_since(updated)
                    impact,label = temporal_risk(days)
                    return {
                        "email":email, "found":True,
                        "username":uname,
                        "last_active":updated[:10] if updated else None,
                        "days_inactive":days,
                        "activity_label":label,
                        "impact":impact,
                    }
        except: pass
    return {"email":email,"found":False,"last_active":None,
            "days_inactive":None,"activity_label":"Not found","impact":0}

async def batch_github(emails_locals, concurrency=30, token=""):
    """emails_locals = [(email, local), ...]"""
    results = {}
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(concurrency)

        async def bounded(email, local):
            async with sem:
                await asyncio.sleep(0.05)  # small delay to avoid rate limit
                return await check_github_async(session, local, email, token)

        tasks = [bounded(e,l) for e,l in emails_locals]
        with tqdm(total=len(tasks), desc="  GitHub  ", unit="email",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for coro in asyncio.as_completed(tasks):
                r = await coro
                results[r["email"]] = r
                pbar.update(1)
    return results


# ─────────────────────────────────────────────────────────────
#  PHASE 4: HIBP (sequential — must respect 1/1.5sec)
#  Run overnight on borderline emails only
# ─────────────────────────────────────────────────────────────
def hibp_sequential(emails, api_key, output_path):
    """
    HIBP MUST be sequential — 1 request per 1.5 seconds (their ToS).
    Run this overnight. Saves results to CSV as it goes.
    For 10,000 emails = ~4 hours.
    For 1 lakh = ~41 hours (run across multiple nights).
    """
    if not api_key:
        print("  No HIBP key provided. Skipping.")
        return {}

    results = {}
    headers = {"hibp-api-key":api_key,"User-Agent":"EmailSanitizer/5.0"}

    # Load existing results to resume
    checkpoint = output_path.replace(".csv","_hibp_checkpoint.json")
    if os.path.exists(checkpoint):
        with open(checkpoint) as f:
            results = json.load(f)
        print(f"  Resumed HIBP from checkpoint ({len(results)} done)")

    remaining = [e for e in emails if e not in results]
    eta_hours = len(remaining)*1.6/3600
    print(f"  HIBP: {len(remaining):,} emails to check. ETA: {eta_hours:.1f} hours")

    for i, email in enumerate(tqdm(remaining, desc="  HIBP    ", unit="email")):
        try:
            url = (f"https://haveibeenpwned.com/api/v3/"
                   f"breachedaccount/{email}?truncateResponse=false")
            resp = requests.get(url, headers=headers, timeout=8)

            if resp.status_code == 200:
                breaches = resp.json()
                years = []
                for b in breaches:
                    try: years.append(int(b.get("BreachDate","2000")[:4]))
                    except: pass
                most_recent = max(years) if years else None
                days_approx = (datetime.now().year - most_recent)*365 if most_recent else None
                impact,label = temporal_risk(days_approx)
                impact = max(impact, -10)  # Cap HIBP impact

                results[email] = {
                    "found":True, "breach_count":len(breaches),
                    "most_recent":most_recent,
                    "days_approx":days_approx,
                    "activity_label":label, "impact":impact,
                    "email_age": (datetime.now().year - min(years)) if years else None,
                }
            elif resp.status_code == 404:
                results[email] = {"found":False,"impact":+8,
                                   "activity_label":"Never seen publicly"}
            elif resp.status_code == 401:
                print("\n  ❌ Invalid HIBP API key"); break
            elif resp.status_code == 429:
                print("\n  ⚠️ Rate limited. Waiting 3 seconds...")
                time.sleep(3)
                continue

        except Exception as e:
            results[email] = {"found":False,"impact":0,"error":str(e)}

        # Save checkpoint every 500 emails
        if (i+1) % 500 == 0:
            with open(checkpoint,"w") as f:
                json.dump(results, f)

        time.sleep(1.6)  # Respect HIBP rate limit

    # Final checkpoint save
    with open(checkpoint,"w") as f:
        json.dump(results, f)

    return results


# ─────────────────────────────────────────────────────────────
#  PHASE 5: IPQS (for borderline emails, saves free credits)
# ─────────────────────────────────────────────────────────────
async def check_ipqs_async(session, email, key):
    try:
        url    = f"https://ipqualityscore.com/api/json/email/{key}/{email}"
        params = {"timeout":7,"abuse_strictness":1}
        async with session.get(url, params=params,
                               timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                d = await resp.json()
                if d.get("success"):
                    fraud  = d.get("fraud_score",0)
                    trap   = d.get("spam_trap_score",0)
                    abuse  = d.get("recent_abuse",False)
                    active = d.get("valid",False)
                    impact = 0
                    if trap > 0.5: impact += 60
                    if fraud > 75: impact += 40
                    elif fraud > 50: impact += 20
                    elif fraud < 25: impact -= 10
                    if abuse: impact += 30
                    if not active: impact += 25
                    if active and not abuse: impact -= 15
                    return {"email":email,"checked":True,"fraud_score":fraud,
                            "spam_trap":trap>0.5,"recent_abuse":abuse,
                            "active":active,"impact":impact}
    except: pass
    return {"email":email,"checked":False,"impact":0}

async def batch_ipqs(emails, key, concurrency=5):
    """
    IPQS: Use concurrency=5 max to avoid burning through credits too fast.
    Smart: only called on borderline emails anyway.
    """
    results = {}
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(concurrency)

        async def bounded(email):
            async with sem:
                await asyncio.sleep(0.2)
                return await check_ipqs_async(session, email, key)

        tasks = [bounded(e) for e in emails]
        with tqdm(total=len(tasks), desc="  IPQS    ", unit="email") as pbar:
            for coro in asyncio.as_completed(tasks):
                r = await coro
                results[r["email"]] = r
                pbar.update(1)
    return results


# ─────────────────────────────────────────────────────────────
#  FINAL SCORER
# ─────────────────────────────────────────────────────────────
def compute_final(local_r, grav_r, gh_r, hibp_r, ipqs_r):
    """Combines all phase results into final risk score."""
    score   = local_r["local_score"]
    reasons = list(local_r.get("local_reasons",[]))
    last_active = None
    last_source = ""
    days_inactive = None

    # Gravatar
    if grav_r and grav_r.get("found"):
        score += grav_r["impact"]
        reasons.append("Gravatar profile found")

    # GitHub (has temporal scoring built in)
    if gh_r and gh_r.get("found"):
        score += gh_r["impact"]
        days_inactive = gh_r.get("days_inactive")
        last_active   = gh_r.get("last_active")
        last_source   = "GitHub"
        reasons.append(f"GitHub: {gh_r.get('activity_label','')}")

    # HIBP (fixed recency logic)
    if hibp_r and hibp_r.get("found"):
        hibp_impact = hibp_r.get("impact",0)
        score += hibp_impact
        if days_inactive is None:
            days_inactive = hibp_r.get("days_approx")
            last_source   = "HIBP"
        reasons.append(f"HIBP: {hibp_r.get('activity_label','')}")
    elif hibp_r and not hibp_r.get("found"):
        score += hibp_r.get("impact", 0)

    # IPQS
    if ipqs_r and ipqs_r.get("checked"):
        score += ipqs_r.get("impact",0)
        if ipqs_r.get("spam_trap"): score = 100; reasons.append("IPQS: SPAM TRAP")
        if ipqs_r.get("recent_abuse"): reasons.append("IPQS: Recent abuse")
        if not ipqs_r.get("active"): reasons.append("IPQS: Mailbox not active")

    score = max(0, min(score, 100))

    if score <= 20:   level,action = "LOW","KEEP"
    elif score <= 40: level,action = "MEDIUM","MONITOR"
    elif score <= 65: level,action = "HIGH","RE-ENGAGE"
    else:             level,action = "CRITICAL","REMOVE"

    return {
        "email":          local_r["email"],
        "risk_score":     score,
        "risk_level":     level,
        "action":         action,
        "last_active":    last_active,
        "last_active_src":last_source,
        "days_inactive":  days_inactive,
        "is_spam_trap":   local_r.get("is_spam_trap",False),
        "is_disposable":  local_r.get("is_disposable",False),
        "is_typo":        local_r.get("is_typo",False),
        "typo_fix":       local_r.get("typo_fix",""),
        "is_role":        local_r.get("is_role",False),
        "username_risk":  local_r.get("username_risk",""),
        "entropy":        local_r.get("entropy",0),
        "gravatar":       bool(grav_r and grav_r.get("found")),
        "github":         bool(gh_r and gh_r.get("found")),
        "hibp_breaches":  hibp_r.get("breach_count",0) if hibp_r else 0,
        "ipqs_fraud":     ipqs_r.get("fraud_score") if ipqs_r else None,
        "reasons":        " | ".join(reasons) if reasons else "Clean",
    }


# ─────────────────────────────────────────────────────────────
#  CHECKPOINT SYSTEM
# ─────────────────────────────────────────────────────────────
class Checkpoint:
    def __init__(self, base_path):
        self.path = base_path + "_checkpoint.json"

    def save(self, data: dict):
        with open(self.path,"w") as f:
            json.dump(data, f)

    def load(self) -> dict:
        if os.path.exists(self.path):
            with open(self.path) as f:
                return json.load(f)
        return {}

    def exists(self): return os.path.exists(self.path)
    def delete(self): os.remove(self.path) if self.exists() else None


# ─────────────────────────────────────────────────────────────
#  MAIN BATCH PIPELINE
# ─────────────────────────────────────────────────────────────
async def run_pipeline(args):
    import requests  # For HIBP sequential

    start_time = time.time()

    # Setup output directory
    out_dir = Path(args.output or CONFIG["output_dir"])
    out_dir.mkdir(exist_ok=True)
    base_name = Path(args.file).stem

    print(f"\n{'='*60}")
    print(f"  EMAIL SANITIZER — BATCH PROCESSOR")
    print(f"  File: {args.file}")
    print(f"{'='*60}\n")

    # ── LOAD FILE ─────────────────────────────────────────────
    print("📂 Loading file...")
    if args.file.endswith(".csv"):
        df = pd.read_csv(args.file, dtype=str, low_memory=False)
    else:
        df = pd.read_excel(args.file, dtype=str)
    df = df.fillna("")

    email_col = args.email_col or "email"
    if email_col not in df.columns:
        # Try to auto-detect
        for c in df.columns:
            if "email" in c.lower() or "mail" in c.lower():
                email_col = c; break

    print(f"  Loaded {len(df):,} rows from column '{email_col}'")

    # Deduplicate
    df["_norm"] = df[email_col].str.strip().str.lower()
    dupes = len(df) - len(df.drop_duplicates(subset=["_norm"]))
    df = df.drop_duplicates(subset=["_norm"]).reset_index(drop=True)
    print(f"  Removed {dupes:,} duplicates → {len(df):,} unique emails")

    emails = df[email_col].str.strip().str.lower().tolist()

    # ── CHECKPOINT: Resume support ─────────────────────────────
    cp = Checkpoint(str(out_dir / base_name))
    saved = cp.load() if args.resume and cp.exists() else {}
    done_emails = set(saved.keys())

    # ── PHASE 1: LOCAL VALIDATION (all emails, instant) ────────
    print(f"\n{'─'*50}")
    print(f"PHASE 1: Local Validation (instant, no network)")
    print(f"{'─'*50}")

    local_results = {}
    if done_emails:
        emails_to_local = [e for e in emails if e not in done_emails]
        # Restore saved results
        for e,r in saved.items():
            local_results[e] = r.get("local",{})
    else:
        emails_to_local = emails

    with tqdm(total=len(emails_to_local), desc="  Local   ", unit="email",
              bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
        for email in emails_to_local:
            local_results[email] = local_validate(email)
            pbar.update(1)

    # Stats
    total       = len(emails)
    terminal    = sum(1 for r in local_results.values() if r.get("terminal"))
    needs_api   = sum(1 for r in local_results.values() if r.get("needs_api"))
    big_provider= sum(1 for r in local_results.values() if r.get("is_big_provider"))

    print(f"\n  ✅ Done. Results:")
    print(f"     Total emails:     {total:,}")
    print(f"     Immediately bad:  {terminal:,} ({terminal/total*100:.1f}%)")
    print(f"     Big providers:    {big_provider:,}")
    print(f"     Need API checks:  {needs_api:,}")
    print(f"     Saved directly:   {total-needs_api-terminal:,} (clearly safe/bad)")

    # Get emails that need API checks
    api_emails = [e for e,r in local_results.items()
                  if r.get("needs_api") and e not in done_emails]

    # ── PHASE 2: GRAVATAR (async) ──────────────────────────────
    grav_results = {}
    if api_emails:
        print(f"\n{'─'*50}")
        eta = len(api_emails)/50/60
        print(f"PHASE 2: Gravatar Check ({len(api_emails):,} emails, ETA ~{eta:.0f} min)")
        print(f"{'─'*50}")
        grav_results = await batch_gravatar(
            api_emails,
            concurrency=args.concurrency or CONFIG["gravatar_concurrency"])
        found = sum(1 for r in grav_results.values() if r.get("found"))
        print(f"  ✅ Gravatar profiles found: {found:,}")

    # ── PHASE 3: GITHUB (async) ────────────────────────────────
    gh_results = {}
    # Only check GitHub on emails where Gravatar not confirmed
    github_emails = [(e, e.split("@")[0])
                     for e in api_emails
                     if not (grav_results.get(e,{}).get("found"))]

    if github_emails:
        print(f"\n{'─'*50}")
        eta = len(github_emails)/30/60
        print(f"PHASE 3: GitHub Check ({len(github_emails):,} emails, ETA ~{eta:.0f} min)")
        if not args.github_token:
            print(f"  ⚠️  No GitHub token → 60 req/hr limit (much slower)")
            print(f"  💡 Get free token: github.com → Settings → Developer Settings")
        print(f"{'─'*50}")
        gh_results = await batch_github(
            github_emails,
            concurrency=args.concurrency or CONFIG["github_concurrency"],
            token=args.github_token or "")
        found = sum(1 for r in gh_results.values() if r.get("found"))
        print(f"  ✅ GitHub accounts found: {found:,}")

    # ── PHASE 4: HIBP (sequential — run if not skipped) ────────
    hibp_results = {}
    if args.hibp_key and not args.skip_hibp:
        # Only run HIBP on emails still uncertain (no gravatar AND no github)
        hibp_emails = [e for e in api_emails
                       if not (grav_results.get(e,{}).get("found") or
                               gh_results.get(e,{}).get("found"))]

        print(f"\n{'─'*50}")
        eta = len(hibp_emails)*1.6/3600
        print(f"PHASE 4: HIBP (sequential — {len(hibp_emails):,} emails)")
        print(f"  ETA: {eta:.1f} hours. Use --skip-hibp to skip and run overnight.")
        print(f"{'─'*50}")
        hibp_results = hibp_sequential(
            hibp_emails, args.hibp_key,
            str(out_dir / base_name))
        found = sum(1 for r in hibp_results.values() if r.get("found"))
        print(f"  ✅ HIBP breaches found: {found:,}")
    elif not args.hibp_key:
        print(f"\n  💡 HIBP skipped (no key). Get free key: haveibeenpwned.com/API/Key")

    # ── PHASE 5: IPQS (borderline only) ───────────────────────
    ipqs_results = {}
    if args.ipqs_key:
        # Only borderline emails (score 20-75) that are still uncertain
        ipqs_emails = []
        for e in api_emails:
            lv = local_results.get(e,{})
            fp_impact = (grav_results.get(e,{}).get("impact",0) +
                        gh_results.get(e,{}).get("impact",0) +
                        hibp_results.get(e,{}).get("impact",0))
            pre_score = min(max(lv.get("local_score",0)+fp_impact,0),100)
            if 20 <= pre_score <= 75:
                ipqs_emails.append(e)

        if ipqs_emails:
            print(f"\n{'─'*50}")
            print(f"PHASE 5: IPQS ({len(ipqs_emails):,} borderline emails)")
            print(f"  Free credits used: {len(ipqs_emails):,} of 1,000 this month")
            print(f"{'─'*50}")
            ipqs_results = await batch_ipqs(ipqs_emails, args.ipqs_key)
            checked = sum(1 for r in ipqs_results.values() if r.get("checked"))
            print(f"  ✅ IPQS checked: {checked:,}")

    # ── COMBINE ALL RESULTS ─────────────────────────────────────
    print(f"\n{'─'*50}")
    print("Combining all results...")
    final_results = []

    for email in emails:
        lv   = local_results.get(email, {"email":email,"local_score":0})
        gv   = grav_results.get(email)
        ghv  = gh_results.get(email)
        hbv  = hibp_results.get(email)
        iqv  = ipqs_results.get(email)
        final_results.append(compute_final(lv,gv,ghv,hbv,iqv))

    rdf = pd.DataFrame(final_results)

    # ── EXPORT RESULTS ─────────────────────────────────────────
    print(f"\n{'─'*50}")
    print("Saving results...")

    # Full report
    full_path = out_dir / f"{base_name}_full_report.csv"
    rdf.to_csv(full_path, index=False)
    print(f"  📋 Full report:   {full_path} ({len(rdf):,} rows)")

    # Split by action
    for level, fname, icon in [
        ("LOW",      "safe_emails.csv",     "✅"),
        ("MEDIUM",   "monitor_emails.csv",  "⚠️ "),
        ("HIGH",     "reengage_emails.csv", "🔄"),
        ("CRITICAL", "remove_emails.csv",   "🚨"),
    ]:
        subset = rdf[rdf["risk_level"]==level][["email","risk_score","reasons"]]
        path   = out_dir / f"{base_name}_{fname}"
        subset.to_csv(path, index=False)
        pct    = len(subset)/len(rdf)*100 if len(rdf) else 0
        print(f"  {icon} {level:8}: {path.name} ({len(subset):,} emails, {pct:.1f}%)")

    # Summary
    elapsed = time.time()-start_time
    print(f"\n{'='*60}")
    print(f"  COMPLETE!")
    print(f"  Total processed:  {len(rdf):,}")
    print(f"  Safe to send:     {len(rdf[rdf['risk_level']=='LOW']):,}")
    print(f"  Remove:           {len(rdf[rdf['risk_level']=='CRITICAL']):,}")
    print(f"  Time taken:       {elapsed/60:.1f} minutes")
    print(f"  Output folder:    {out_dir}/")
    print(f"{'='*60}\n")

    # Clean checkpoint
    cp.delete()


# ─────────────────────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────
def main():
    import requests  # Used in hibp_sequential

    parser = argparse.ArgumentParser(
        description="Email Sanitizer Batch Processor — For Lakh Scale",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic run (local checks + Gravatar + GitHub):
  python batch_processor.py --file emails.csv

  # Full run with all checks:
  python batch_processor.py --file emails.csv --hibp-key YOUR_KEY --ipqs-key YOUR_KEY

  # Fast run (skip HIBP, do it overnight):
  python batch_processor.py --file emails.csv --skip-hibp --github-token YOUR_TOKEN

  # Resume after crash:
  python batch_processor.py --file emails.csv --resume

  # High concurrency for faster Gravatar:
  python batch_processor.py --file emails.csv --concurrency 100

SPEED ESTIMATES (1 lakh emails):
  Local checks:    2 minutes    (always runs)
  Gravatar:        33 minutes   (50 concurrent)
  GitHub:          17 minutes   (30 concurrent + token)
  HIBP:            41 hours     (sequential — run overnight)
  IPQS:            borderline only, ~10-15 min
        """
    )
    parser.add_argument("--file",         required=True, help="Input CSV or Excel file")
    parser.add_argument("--email-col",    default="email",  help="Email column name")
    parser.add_argument("--concurrency",  type=int, default=50, help="Parallel HTTP requests")
    parser.add_argument("--chunk",        type=int, default=1000, help="Checkpoint every N rows")
    parser.add_argument("--skip-hibp",    action="store_true", help="Skip HIBP check")
    parser.add_argument("--github-token", default="", help="GitHub personal access token")
    parser.add_argument("--hibp-key",     default="", help="HIBP API key")
    parser.add_argument("--ipqs-key",     default="", help="IPQS API key")
    parser.add_argument("--output",       default="output", help="Output directory")
    parser.add_argument("--resume",       action="store_true", help="Resume from checkpoint")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        sys.exit(1)

    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    # Need requests for HIBP sequential
    try:
        import requests
    except ImportError:
        print("Run: pip install requests")
        sys.exit(1)
    main()

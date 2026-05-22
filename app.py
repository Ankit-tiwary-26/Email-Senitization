"""
================================================================
  EMAIL SANITIZATION SYSTEM
  Streamlit Web App — Full Pipeline
  
  Designed for datasets that are 95% Gmail/Yahoo/Hotmail
================================================================
"""

import streamlit as st
import pandas as pd
import re
import socket
import time
import random
import io
from datetime import datetime, timedelta
from difflib import SequenceMatcher

# Optional DNS
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Email Sanitization System",
    page_icon="🧹",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────
#  STYLING
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem;
        border-radius: 12px;
        text-align: center;
        margin-bottom: 2rem;
    }
    .main-header h1 { color: #e94560; font-size: 2.2rem; margin: 0; }
    .main-header p  { color: #a8b2d8; margin: 0.5rem 0 0 0; font-size: 1rem; }

    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        border: 1px solid #2a2a3e;
    }
    .metric-card .number { font-size: 2rem; font-weight: bold; }
    .metric-card .label  { color: #a8b2d8; font-size: 0.85rem; margin-top: 0.3rem; }

    .safe     { color: #00d4aa; }
    .medium   { color: #ffd700; }
    .high     { color: #ff6b35; }
    .critical { color: #e94560; }

    .info-box {
        background: #1e2a3a;
        border-left: 4px solid #0f3460;
        padding: 1rem 1.2rem;
        border-radius: 0 8px 8px 0;
        margin: 1rem 0;
    }
    .warn-box {
        background: #2a1f0e;
        border-left: 4px solid #ffd700;
        padding: 1rem 1.2rem;
        border-radius: 0 8px 8px 0;
        margin: 1rem 0;
    }
    .stProgress .st-bo { background: #e94560; }

    div[data-testid="stDataFrame"] { border-radius: 8px; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  DATA CONSTANTS
# ─────────────────────────────────────────────────────────────

BIG_PROVIDERS = {
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.com.au",
    "yahoo.ca", "yahoo.fr", "yahoo.de", "ymail.com", "rocketmail.com",
    "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.in",
    "outlook.com", "outlook.in", "outlook.co.uk",
    "live.com", "live.co.uk", "live.in", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "rediffmail.com", "protonmail.com", "proton.me",
}

TYPO_MAP = {
    # Gmail
    "gmial.com":"gmail.com","gmaill.com":"gmail.com","gmal.com":"gmail.com",
    "gmai.com":"gmail.com","gmali.com":"gmail.com","gmail.co":"gmail.com",
    "gmail.cm":"gmail.com","gmail.cmo":"gmail.com","gmail.con":"gmail.com",
    "gnail.com":"gmail.com","gamil.com":"gmail.com","gmaim.com":"gmail.com",
    "gemail.com":"gmail.com","gmail.ocm":"gmail.com","gmailcom":"gmail.com",
    # Yahoo
    "yaho.com":"yahoo.com","yahooo.com":"yahoo.com","yhoo.com":"yahoo.com",
    "yhaoo.com":"yahoo.com","yahoo.co":"yahoo.com","yahoo.cm":"yahoo.com",
    "yaoo.com":"yahoo.com","ahoo.com":"yahoo.com","yahoo.cmo":"yahoo.com",
    "yaho.co.in":"yahoo.co.in","yahoomail.com":"yahoo.com",
    # Hotmail
    "hotmai.com":"hotmail.com","hotmial.com":"hotmail.com",
    "hotmaill.com":"hotmail.com","hotmal.com":"hotmail.com",
    "hotmali.com":"hotmail.com","hotmail.co":"hotmail.com",
    "hotmail.cm":"hotmail.com","hotmail.cmo":"hotmail.com",
    "homail.com":"hotmail.com","hotmeil.com":"hotmail.com",
    # Outlook
    "outlok.com":"outlook.com","outloo.com":"outlook.com",
    "outllok.com":"outlook.com","outlook.co":"outlook.com",
    "otlook.com":"outlook.com","ourlook.com":"outlook.com",
    # Rediff
    "rediff.com":"rediffmail.com","redifmail.com":"rediffmail.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com","mailinator.net","yopmail.com","yopmail.fr",
    "tempmail.com","temp-mail.org","temp-mail.io","tempmail.net",
    "tempr.email","10minutemail.com","10minutemail.net","10minutemail.org",
    "guerrillamail.com","guerrillamail.info","guerrillamail.biz",
    "guerrillamail.de","guerrillamail.net","guerrillamail.org",
    "sharklasers.com","grr.la","spam4.me","trashmail.com","trashmail.me",
    "trashmail.net","trashmail.at","trashmail.io","trashmail.xyz",
    "mohmal.com","mytemp.email","discard.email","maildrop.cc",
    "fakeinbox.com","throwam.com","throwaway.email","getairmail.com",
    "mailnesia.com","dispostable.com",
}

SPAM_TRAP_DOMAINS = {
    "spamtrap.ro","spamgourmet.com","spamgourmet.net","spamgourmet.org",
    "spamhole.com","spamcop.net","spam.la","spamex.com",
    "mailnull.com","deadaddress.com","darkharvestspam.com",
    "trap.email","spamtrap.com","spamtrap.net",
    "example.com","example.net","example.org",
    "test.com","invalid.com","nowhere.com",
}

ROLE_PREFIXES = {
    "admin","administrator","webmaster","hostmaster","postmaster",
    "info","information","contact","hello","support","help","helpdesk",
    "service","customer","care","sales","marketing","billing","accounts",
    "noreply","no-reply","donotreply","do-not-reply",
    "abuse","spam","security","privacy","hr","jobs","careers",
    "newsletter","news","updates","alerts","root","sys","system",
    "press","media","legal","compliance","team","office","mail",
}

EMAIL_REGEX = re.compile(
    r"^(?!.*\.\.)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    re.IGNORECASE
)

# Username risk patterns
PAT_RANDOM      = re.compile(r"^[bcdfghjklmnpqrstvwxyz]{5,}$")
PAT_LONG_NUM    = re.compile(r"^[a-z]+\d{6,}$")
PAT_PURE_NUM    = re.compile(r"^\d+$")
PAT_SUSPICIOUS  = re.compile(
    r"(temp|test|spam|trap|fake|dummy|null|noreply|delete|"
    r"removed|invalid|bounce|dead|block)", re.IGNORECASE
)


# ─────────────────────────────────────────────────────────────
#  MX CACHE (avoid repeated DNS lookups for same domain)
# ─────────────────────────────────────────────────────────────
_mx_cache = {}

def check_mx(domain: str) -> bool:
    """Check if domain has MX record. Cached."""
    if domain in _mx_cache:
        return _mx_cache[domain]
    if not DNS_AVAILABLE:
        _mx_cache[domain] = True  # Assume valid if no DNS lib
        return True
    try:
        dns.resolver.resolve(domain, "MX")
        _mx_cache[domain] = True
        return True
    except Exception:
        try:
            dns.resolver.resolve(domain, "A")
            _mx_cache[domain] = True
            return True
        except Exception:
            _mx_cache[domain] = False
            return False


# ─────────────────────────────────────────────────────────────
#  CORE VALIDATION ENGINE
# ─────────────────────────────────────────────────────────────

def validate_email(row_data: dict, config: dict) -> dict:
    """
    Full validation pipeline for one email.
    
    row_data keys:
        email           : the email address (required)
        last_engaged    : last open/click date string YYYY-MM-DD (optional)
        date_added      : when added to list YYYY-MM-DD (optional)
    
    config keys:
        check_mx        : bool
        engagement_col  : column name for engagement date
        added_col       : column name for date added
        inactivity_days : threshold for HIGH risk (default 365)
    
    RETURNS dict with all validation fields
    """
    email = str(row_data.get("email", "")).strip().lower()
    
    result = {
        "email":            email,
        "status":           "UNKNOWN",
        "risk_level":       "UNKNOWN",
        "risk_score":       0,
        "action":           "",
        "is_valid_syntax":  False,
        "is_typo":          False,
        "typo_suggestion":  "",
        "is_disposable":    False,
        "is_spam_trap":     False,
        "is_role_based":    False,
        "is_big_provider":  False,
        "provider":         "",
        "username_risk":    "LOW",
        "engagement_risk":  "UNKNOWN",
        "days_inactive":    None,
        "reasons":          [],
    }

    score = 0

    # ── LAYER 1: EMPTY CHECK ──────────────────────────────────
    if not email or "@" not in email:
        result["status"]    = "INVALID"
        result["risk_score"]= 100
        result["risk_level"]= "CRITICAL"
        result["reasons"]   = ["Empty or missing email"]
        result["action"]    = "REMOVE"
        return result

    local, domain = email.split("@", 1)

    # ── LAYER 2: SYNTAX ───────────────────────────────────────
    if not EMAIL_REGEX.match(email):
        result["status"]      = "INVALID_SYNTAX"
        result["risk_score"]  = 100
        result["risk_level"]  = "CRITICAL"
        result["reasons"]     = ["Invalid email format/syntax"]
        result["action"]      = "REMOVE"
        return result

    result["is_valid_syntax"] = True

    # ── LAYER 3: SPAM TRAP DOMAIN ─────────────────────────────
    if domain in SPAM_TRAP_DOMAINS:
        result["is_spam_trap"] = True
        result["status"]       = "SPAM_TRAP"
        result["risk_score"]   = 100
        result["risk_level"]   = "CRITICAL"
        result["reasons"]      = [f"'{domain}' is a known spam trap domain"]
        result["action"]       = "REMOVE IMMEDIATELY"
        return result

    # ── LAYER 4: TYPO DETECTION ───────────────────────────────
    if domain in TYPO_MAP:
        result["is_typo"]        = True
        result["typo_suggestion"]= TYPO_MAP[domain]
        score += 65
        result["reasons"].append(
            f"Typo domain '{domain}' → did you mean '{TYPO_MAP[domain]}'?"
        )
    else:
        # Fuzzy match check
        for provider in BIG_PROVIDERS:
            sim = SequenceMatcher(None, domain, provider).ratio()
            if 0.82 <= sim < 1.0:
                result["is_typo"]         = True
                result["typo_suggestion"] = provider
                score += 55
                result["reasons"].append(
                    f"'{domain}' looks like a typo of '{provider}' ({int(sim*100)}% match)"
                )
                break

    # ── LAYER 5: DISPOSABLE ───────────────────────────────────
    if domain in DISPOSABLE_DOMAINS:
        result["is_disposable"] = True
        score += 70
        result["reasons"].append(f"'{domain}' is a disposable/temporary email provider")

    # ── LAYER 6: ROLE-BASED ───────────────────────────────────
    base_local = local.split("+")[0]
    if base_local in ROLE_PREFIXES:
        result["is_role_based"] = True
        score += 25
        result["reasons"].append(f"Role-based address ('{base_local}') — goes to department not person")

    # ── LAYER 7: BIG PROVIDER FLAG ───────────────────────────
    if domain in BIG_PROVIDERS:
        result["is_big_provider"] = True
        result["provider"]        = domain

    # ── LAYER 8: USERNAME PATTERN ANALYSIS ───────────────────
    #    This is the KEY check for Gmail/Yahoo/Hotmail
    #    since SMTP doesn't work on them
    clean_local = local.replace(".", "").replace("_", "").replace("-", "")
    username_score = 0

    if PAT_SUSPICIOUS.search(local):
        username_score += 40
        result["reasons"].append(f"Suspicious keyword in username: '{local}'")

    if PAT_RANDOM.match(clean_local) and len(clean_local) >= 5:
        username_score += 30
        result["reasons"].append(f"Username looks randomly generated (no vowels pattern)")

    if PAT_LONG_NUM.match(local):
        username_score += 20
        result["reasons"].append(f"Auto-generated pattern: name + many numbers")

    if PAT_PURE_NUM.match(local):
        username_score += 25
        result["reasons"].append(f"Username is purely numeric — unusual for real person")

    if len(local) <= 2:
        username_score += 20
        result["reasons"].append(f"Username too short ({len(local)} chars)")

    if len(local) > 30:
        username_score += 15
        result["reasons"].append(f"Username unusually long ({len(local)} chars)")

    if username_score >= 40:
        result["username_risk"] = "HIGH"
    elif username_score >= 20:
        result["username_risk"] = "MEDIUM"

    score += username_score

    # ── LAYER 9: MX RECORD CHECK (skip big providers — always valid) ──
    if not result["is_big_provider"] and config.get("check_mx", True):
        if not check_mx(domain):
            score += 90
            result["reasons"].append(f"No MX record — domain cannot receive email")
            result["status"] = "NO_MX"

    # ── LAYER 10: ENGAGEMENT / INACTIVITY (KEY for Gmail traps) ──
    engaged_col = config.get("engagement_col")
    last_engaged_raw = row_data.get(engaged_col) if engaged_col else None
    threshold   = config.get("inactivity_days", 365)

    if last_engaged_raw and str(last_engaged_raw).strip() not in ("", "nan", "None", "NaT"):
        try:
            last_engaged = pd.to_datetime(str(last_engaged_raw))
            days = (datetime.now() - last_engaged.to_pydatetime()).days
            result["days_inactive"] = days

            if days < 90:
                result["engagement_risk"] = "LOW"
            elif days < 180:
                result["engagement_risk"] = "MEDIUM"
                score += 20
                result["reasons"].append(f"No engagement for {days} days")
            elif days < threshold:
                result["engagement_risk"] = "HIGH"
                score += 40
                result["reasons"].append(f"No engagement for {days} days — HIGH recycled trap risk")
            else:
                result["engagement_risk"] = "CRITICAL"
                score += 65
                result["reasons"].append(
                    f"No engagement for {days} days ({days//365}+ year) — "
                    f"likely inactive/recycled spam trap"
                )
        except Exception:
            result["engagement_risk"] = "UNKNOWN"
            score += 15
    else:
        result["engagement_risk"] = "UNKNOWN"
        score += 10  # Small penalty for missing data

    # ── LAYER 11: LIST AGE ────────────────────────────────────
    added_col     = config.get("added_col")
    added_raw     = row_data.get(added_col) if added_col else None

    if added_raw and str(added_raw).strip() not in ("", "nan", "None", "NaT"):
        try:
            added_date = pd.to_datetime(str(added_raw))
            age_days   = (datetime.now() - added_date.to_pydatetime()).days

            if age_days > 730:    # > 2 years
                score += 35
                result["reasons"].append(f"Record is {age_days//365}+ years old — high inactivity risk")
            elif age_days > 365:  # 1-2 years
                score += 15
                result["reasons"].append(f"Record is {age_days} days old — moderate age risk")
        except Exception:
            pass

    # ── FINAL SCORING & CLASSIFICATION ───────────────────────
    score = min(score, 100)
    result["risk_score"] = score

    if result["is_spam_trap"] or result["is_typo"] or result["is_disposable"]:
        if score >= 65:
            result["risk_level"] = "CRITICAL"
            result["status"]     = result.get("status", "RISKY")
            result["action"]     = "REMOVE"
        else:
            result["risk_level"] = "HIGH"
            result["action"]     = "REVIEW"
    elif score <= 20:
        result["risk_level"] = "LOW"
        result["status"]     = "SAFE"
        result["action"]     = "KEEP"
    elif score <= 40:
        result["risk_level"] = "MEDIUM"
        result["status"]     = "MEDIUM RISK"
        result["action"]     = "MONITOR"
    elif score <= 65:
        result["risk_level"] = "HIGH"
        result["status"]     = "HIGH RISK"
        result["action"]     = "RE-ENGAGE FIRST"
    else:
        result["risk_level"] = "CRITICAL"
        result["status"]     = "CRITICAL RISK"
        result["action"]     = "REMOVE"

    return result


# ─────────────────────────────────────────────────────────────
#  STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def main():

    # ── HEADER ────────────────────────────────────────────────
    st.markdown("""
    <div class="main-header">
        <h1>🧹 Email Sanitization System</h1>
        <p>Spam Trap Detection · Bulk Email Hygiene · Risk Scoring</p>
    </div>
    """, unsafe_allow_html=True)

    # ── SIDEBAR CONFIG ─────────────────────────────────────────
    with st.sidebar:
        st.markdown("### ⚙️ Settings")
        st.markdown("---")

        check_mx_records = st.toggle("Check MX Records (DNS)", value=True,
            help="Verify if domain has a mail server. Skip for faster processing.")

        inactivity_threshold = st.slider(
            "Inactivity Threshold (days)",
            min_value=90, max_value=730, value=365, step=30,
            help="Emails not engaged beyond this many days = CRITICAL risk"
        )

        st.markdown("---")
        st.markdown("### 📊 Risk Level Guide")
        st.markdown("""
        🟢 **LOW (0-20)** — Safe to send  
        🟡 **MEDIUM (21-40)** — Monitor  
        🟠 **HIGH (41-65)** — Re-engage first  
        🔴 **CRITICAL (66+)** — Remove immediately
        """)

        st.markdown("---")
        st.markdown("### ⚠️ Gmail/Yahoo Reality")
        st.markdown("""
        For big providers:
        - SMTP check won't work
        - Detection is **behavioral**
        - Engagement data = most important signal
        - No system can 100% detect Gmail traps
        """)

    # ── TABS ──────────────────────────────────────────────────
    tab1, tab2, tab3 = st.tabs(["📤 Upload & Process", "📊 Results & Download", "📖 Methodology"])

    # ════════════════════════════════════════════════════════
    # TAB 1 — UPLOAD
    # ════════════════════════════════════════════════════════
    with tab1:
        st.markdown("### Step 1 — Upload Your Email List")
        st.markdown("""
        <div class="info-box">
        Upload a <b>CSV or Excel (.xlsx)</b> file.<br>
        Your file must have at least one column with email addresses.<br>
        Optional: include <b>last engagement date</b> and <b>date added</b> columns for better Gmail trap detection.
        </div>
        """, unsafe_allow_html=True)

        uploaded_file = st.file_uploader(
            "Upload CSV or Excel file",
            type=["csv", "xlsx", "xls"],
            help="Max recommended: 50,000 rows"
        )

        if uploaded_file:
            # Load file
            try:
                if uploaded_file.name.endswith(".csv"):
                    df = pd.read_csv(uploaded_file, dtype=str)
                else:
                    df = pd.read_excel(uploaded_file, dtype=str)
                df = df.fillna("")
                st.success(f"✅ Loaded **{len(df):,}** rows, **{len(df.columns)}** columns")
                st.dataframe(df.head(5), use_container_width=True)
            except Exception as e:
                st.error(f"❌ Could not read file: {e}")
                return

            st.markdown("### Step 2 — Map Your Columns")
            col1, col2, col3 = st.columns(3)

            cols = ["(none)"] + list(df.columns)

            with col1:
                email_col = st.selectbox(
                    "📧 Email Column *",
                    options=list(df.columns),
                    index=0,
                    help="Required — the column containing email addresses"
                )
            with col2:
                engaged_col = st.selectbox(
                    "📅 Last Engagement Date",
                    options=cols,
                    index=0,
                    help="Date the person last opened/clicked. Most important for Gmail trap detection."
                )
            with col3:
                added_col = st.selectbox(
                    "📆 Date Added to List",
                    options=cols,
                    index=0,
                    help="When this email was added to your database."
                )

            engaged_col = None if engaged_col == "(none)" else engaged_col
            added_col   = None if added_col   == "(none)" else added_col

            if not engaged_col:
                st.markdown("""
                <div class="warn-box">
                ⚠️ <b>No engagement date column mapped.</b><br>
                For Gmail/Yahoo/Hotmail (95% of your data), engagement date is the
                <b>most critical signal</b> for detecting recycled spam traps.
                If you have this data in your ESP (Mailchimp/SendGrid etc.), add it to your file.
                </div>
                """, unsafe_allow_html=True)

            st.markdown("### Step 3 — Start Processing")
            if st.button("🚀 Run Email Sanitization", type="primary", use_container_width=True):

                config = {
                    "check_mx":        check_mx_records,
                    "inactivity_days": inactivity_threshold,
                    "engagement_col":  engaged_col,
                    "added_col":       added_col,
                }

                # ── DEDUP FIRST ───────────────────────────────
                original_count = len(df)
                df["_email_norm"] = df[email_col].str.strip().str.lower()
                df = df.drop_duplicates(subset=["_email_norm"])
                dupes_removed  = original_count - len(df)

                # ── PROCESS ───────────────────────────────────
                progress_bar = st.progress(0)
                status_text  = st.empty()
                results      = []
                total        = len(df)

                for i, (_, row) in enumerate(df.iterrows()):
                    row_data = {"email": row[email_col]}
                    if engaged_col: row_data[engaged_col] = row.get(engaged_col, "")
                    if added_col:   row_data[added_col]   = row.get(added_col, "")

                    r = validate_email(row_data, config)

                    # Carry original columns too
                    for col in df.columns:
                        if col not in ("_email_norm",) and col not in r:
                            r[f"orig_{col}"] = row.get(col, "")

                    results.append(r)

                    if i % 50 == 0 or i == total - 1:
                        pct = (i + 1) / total
                        progress_bar.progress(pct)
                        status_text.text(
                            f"Processing {i+1:,} / {total:,} emails... "
                            f"({int(pct*100)}%)"
                        )

                status_text.text(f"✅ Done! Processed {total:,} emails.")

                # ── BUILD RESULT DF ───────────────────────────
                result_df = pd.DataFrame(results)

                # Summary counts
                safe     = len(result_df[result_df["risk_level"] == "LOW"])
                medium   = len(result_df[result_df["risk_level"] == "MEDIUM"])
                high     = len(result_df[result_df["risk_level"] == "HIGH"])
                critical = len(result_df[result_df["risk_level"] == "CRITICAL"])
                traps    = len(result_df[result_df["is_spam_trap"] == True])
                typos    = len(result_df[result_df["is_typo"] == True])
                disposable = len(result_df[result_df["is_disposable"] == True])

                st.session_state["result_df"]    = result_df
                st.session_state["dupes_removed"]= dupes_removed
                st.session_state["summary"] = {
                    "total": total, "dupes": dupes_removed,
                    "safe": safe, "medium": medium,
                    "high": high, "critical": critical,
                    "traps": traps, "typos": typos,
                    "disposable": disposable,
                }

                # ── METRICS ───────────────────────────────────
                st.markdown("---")
                st.markdown("### 📊 Results Overview")

                c1, c2, c3, c4, c5 = st.columns(5)
                with c1:
                    st.metric("Total Processed", f"{total:,}")
                with c2:
                    st.metric("Duplicates Removed", f"{dupes_removed:,}")
                with c3:
                    st.metric("✅ Safe", f"{safe:,}",
                              delta=f"{safe/total*100:.1f}%" if total else "0%")
                with c4:
                    st.metric("🔴 Critical", f"{critical:,}",
                              delta=f"-{critical/total*100:.1f}% removed" if total else "0%",
                              delta_color="inverse")
                with c5:
                    st.metric("🚨 Spam Traps", f"{traps:,}")

                st.info("✅ Go to the **Results & Download** tab to see details and download files.")

    # ════════════════════════════════════════════════════════
    # TAB 2 — RESULTS
    # ════════════════════════════════════════════════════════
    with tab2:
        if "result_df" not in st.session_state:
            st.info("👆 Upload and process a file first.")
            return

        result_df = st.session_state["result_df"]
        summary   = st.session_state["summary"]

        st.markdown("### 📊 Full Results")

        # Risk distribution bar
        total = summary["total"]
        if total > 0:
            col1, col2 = st.columns([2, 1])
            with col1:
                pct_safe     = summary["safe"] / total
                pct_medium   = summary["medium"] / total
                pct_high     = summary["high"] / total
                pct_critical = summary["critical"] / total

                st.markdown(f"""
                **Risk Distribution**
                """)
                bar_html = f"""
                <div style="display:flex; height:28px; border-radius:6px; overflow:hidden; margin:0.5rem 0 1rem 0">
                  <div style="width:{pct_safe*100:.1f}%; background:#00d4aa" title="Safe {pct_safe*100:.1f}%"></div>
                  <div style="width:{pct_medium*100:.1f}%; background:#ffd700" title="Medium {pct_medium*100:.1f}%"></div>
                  <div style="width:{pct_high*100:.1f}%; background:#ff6b35" title="High {pct_high*100:.1f}%"></div>
                  <div style="width:{pct_critical*100:.1f}%; background:#e94560" title="Critical {pct_critical*100:.1f}%"></div>
                </div>
                <div style="display:flex; gap:1.5rem; font-size:0.85rem">
                  <span>🟢 Safe {pct_safe*100:.1f}%</span>
                  <span>🟡 Medium {pct_medium*100:.1f}%</span>
                  <span>🟠 High {pct_high*100:.1f}%</span>
                  <span>🔴 Critical {pct_critical*100:.1f}%</span>
                </div>
                """
                st.markdown(bar_html, unsafe_allow_html=True)

            with col2:
                st.markdown(f"""
                | Flag | Count |
                |------|-------|
                | 🚨 Spam Traps | {summary['traps']:,} |
                | ⌨️ Typo Domains | {summary['typos']:,} |
                | ♻️ Disposable | {summary['disposable']:,} |
                | 👥 Duplicates | {summary['dupes']:,} |
                """)

        # ── FILTER ────────────────────────────────────────────
        st.markdown("---")
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            risk_filter = st.multiselect(
                "Filter by Risk Level",
                options=["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"],
                default=["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
            )
        with filter_col2:
            search = st.text_input("Search email", placeholder="Type to search...")

        filtered = result_df[result_df["risk_level"].isin(risk_filter)]
        if search:
            filtered = filtered[filtered["email"].str.contains(search, na=False)]

        # Display columns
        display_cols = ["email", "risk_level", "risk_score", "action",
                        "status", "is_typo", "typo_suggestion",
                        "is_disposable", "is_spam_trap", "is_role_based",
                        "username_risk", "engagement_risk",
                        "days_inactive", "reasons"]
        display_cols = [c for c in display_cols if c in filtered.columns]

        st.dataframe(
            filtered[display_cols].head(500),
            use_container_width=True,
            height=400
        )
        if len(filtered) > 500:
            st.caption(f"Showing 500 of {len(filtered):,} rows. Download for full data.")

        # ── DOWNLOADS ─────────────────────────────────────────
        st.markdown("---")
        st.markdown("### 📥 Download Results")

        d1, d2, d3, d4 = st.columns(4)

        def to_csv_bytes(df):
            return df.to_csv(index=False).encode("utf-8")

        with d1:
            full_csv = to_csv_bytes(result_df[display_cols])
            st.download_button(
                "📋 Full Report (CSV)",
                data=full_csv,
                file_name="full_report.csv",
                mime="text/csv",
                use_container_width=True
            )

        with d2:
            safe_df  = result_df[result_df["risk_level"] == "LOW"][["email"]]
            st.download_button(
                f"✅ Safe Emails ({len(safe_df):,})",
                data=to_csv_bytes(safe_df),
                file_name="safe_emails.csv",
                mime="text/csv",
                use_container_width=True
            )

        with d3:
            remove_df = result_df[result_df["risk_level"] == "CRITICAL"][["email", "risk_score", "reasons"]]
            st.download_button(
                f"🚨 Remove List ({len(remove_df):,})",
                data=to_csv_bytes(remove_df),
                file_name="remove_emails.csv",
                mime="text/csv",
                use_container_width=True
            )

        with d4:
            reengage_df = result_df[result_df["risk_level"] == "HIGH"][["email", "days_inactive"]]
            st.download_button(
                f"🔄 Re-engage List ({len(reengage_df):,})",
                data=to_csv_bytes(reengage_df),
                file_name="reengage_emails.csv",
                mime="text/csv",
                use_container_width=True
            )

    # ════════════════════════════════════════════════════════
    # TAB 3 — METHODOLOGY
    # ════════════════════════════════════════════════════════
    with tab3:
        st.markdown("### 📖 Spam Trap Detection Methodology")

        st.markdown("""
        <div class="warn-box">
        <b>⚠️ Important Reality:</b> No system in the world can 100% identify Gmail/Yahoo/Hotmail 
        spam traps technically. Even paid services like ZeroBounce and NeverBounce use the same 
        heuristic approach. The methodology below is industry-standard.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        ---
        ### Why Gmail Spam Traps Are Different

        | Provider | SMTP Check | DNS Check | Spam Trap Detection |
        |---|---|---|---|
        | `spamtrap.ro` | ✅ Works | ✅ Works | ✅ Easy — it's in our blacklist |
        | `mailinator.com` | ✅ Works | ✅ Works | ✅ Easy — disposable list |
        | **`gmail.com`** | ❌ Always 250 | ✅ Always valid | ❌ **Must use behavioral signals** |
        | **`yahoo.com`** | ❌ Always 250 | ✅ Always valid | ❌ **Must use behavioral signals** |
        | **`hotmail.com`** | ❌ Always 250 | ✅ Always valid | ❌ **Must use behavioral signals** |

        ---
        ### The 11-Layer Detection Pipeline

        | Layer | Check | What It Catches | Risk Added |
        |---|---|---|---|
        | 1 | Empty/Missing | Blank cells | 100 |
        | 2 | Syntax | Bad format (no @, double dots) | 100 |
        | 3 | Spam Trap DB | Known trap domains | 100 |
        | 4 | Typo Detection | gmial.com → gmail.com | +65 |
        | 5 | Disposable | mailinator, yopmail, etc. | +70 |
        | 6 | Role-Based | admin@, info@, noreply@ | +25 |
        | 7 | Big Provider Flag | gmail/yahoo/hotmail tagged | info |
        | 8 | Username Pattern | xk39pl22@ vs john.doe@ | +10 to +40 |
        | 9 | MX Record | Does domain have mail server? | +90 |
        | 10 | **Engagement** | **Days since last open/click** | **+20 to +65** |
        | 11 | **List Age** | **How old is this record?** | **+15 to +35** |

        ---
        ### Risk Score Formula

        ```
        RiskScore = Syntax + SpamTrap + Typo + Disposable + RoleBased 
                  + UsernamePattern + MXRecord + Engagement + ListAge
        
        Final = min(RiskScore, 100)
        ```

        | Score | Risk Level | Action |
        |---|---|---|
        | 0 – 20 | 🟢 LOW | Keep — safe to send |
        | 21 – 40 | 🟡 MEDIUM | Monitor bounce/complaint rates |
        | 41 – 65 | 🟠 HIGH | Send re-engagement email first |
        | 66 – 100 | 🔴 CRITICAL | Remove immediately |

        ---
        ### For Gmail Specifically — Engagement Is Everything

        ```
        Gmail account lifecycle:
        
        Active user           →  Opens emails regularly  →  Safe ✅
               ↓
        Stops using Gmail     →  No opens for 6 months   →  Warning ⚠️ 
               ↓
        Google deactivates    →  No opens for 12 months  →  Danger 🔴
               ↓
        Google recycles it    →  Turned into spam trap   →  🚨 BLACKLIST RISK
        ```

        **Best practice:** Remove anyone who hasn't opened an email in **12 months** 
        from your Gmail/Yahoo/Hotmail segments before they become a trap.
        """)


if __name__ == "__main__":
    main()

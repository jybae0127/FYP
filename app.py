"""
Local processing server for JobTracker AI.
Uses EXACT logic from firstfilter.py and secondfilter.py.
- Fetches emails from Render's /query endpoint
- Runs firstfilter + secondfilter logic locally
- Returns processed data to frontend
- JSON file caching with 24-hour TTL
"""
import os
import re
import json
import time
import hashlib
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
from openai import AzureOpenAI

app = Flask(__name__)
CORS(app)

# Render backend URL for fetching emails
RENDER_URL = "https://gmail-login-backend.onrender.com"

# =========================
# CACHE CONFIGURATION
# =========================
CACHE_FILE = os.path.join(os.path.dirname(__file__), "cache.json")
CACHE_TTL = 24 * 60 * 60  # 24 hours in seconds


def get_cache_key(user_email, start_date, end_date):
    """Generate a unique cache key based on user and date parameters"""
    key_str = f"{user_email or 'unknown'}_{start_date or 'default'}_{end_date or 'now'}"
    return hashlib.md5(key_str.encode()).hexdigest()


def load_cache():
    """Load cache from JSON file"""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_cache(cache):
    """Save cache to JSON file"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save cache: {e}")


def get_user_email():
    """Get the authenticated user's email from Render"""
    try:
        resp = requests.get(f"{RENDER_URL}/user-info", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("email", "unknown")
    except:
        pass
    return "unknown"


def get_cached_result(user_email, start_date, end_date):
    """Get cached result if valid (within TTL)"""
    cache = load_cache()
    key = get_cache_key(user_email, start_date, end_date)

    print(f"\n📦 CACHE CHECK:")
    print(f"   User: {user_email}")
    print(f"   Key: {key}")
    print(f"   Dates: {start_date} to {end_date}")
    print(f"   Cache file: {CACHE_FILE}")
    print(f"   Cache entries: {list(cache.keys())}")

    if key in cache:
        entry = cache[key]
        cached_time = entry.get("timestamp", 0)
        age_seconds = time.time() - cached_time
        if age_seconds < CACHE_TTL:
            print(f"   ✅ Cache HIT (age: {age_seconds/60:.1f} min)")
            return entry.get("data")
        else:
            print(f"   ⏰ Cache EXPIRED (age: {age_seconds/3600:.1f} hours)")
    else:
        print(f"   ❌ Cache MISS - key not found")

    return None


def set_cached_result(user_email, start_date, end_date, data):
    """Store result in cache with timestamp"""
    cache = load_cache()
    key = get_cache_key(user_email, start_date, end_date)

    cache[key] = {
        "timestamp": time.time(),
        "user_email": user_email,
        "start_date": start_date,
        "end_date": end_date,
        "data": data
    }

    # Clean up expired entries
    current_time = time.time()
    cache = {k: v for k, v in cache.items() if current_time - v.get("timestamp", 0) < CACHE_TTL}

    save_cache(cache)
    print(f"\n💾 CACHE SAVE:")
    print(f"   User: {user_email}")
    print(f"   Key: {key}")
    print(f"   Dates: {start_date} to {end_date}")
    print(f"   File: {CACHE_FILE}")
    print(f"   Total entries: {len(cache)}")

# Azure OpenAI Configuration (same as original scripts)
client = AzureOpenAI(
    azure_endpoint="https://api-iw.azure-api.net/sig-shared-jpeast/deployments/gpt-4o-mini/chat/completions?api-version=2025-01-01-preview",
    api_key="72fc700a6bd24963b8e4cf5d28d4e95c",
    api_version="2025-01-01-preview"
)
MODEL = "gpt-4o-mini"

# =========================
# FROM FIRSTFILTER.PY
# =========================
GENERIC_TOKENS = {
    "group", "teams", "page", "career", "careers", "jobs", "job",
    "recruit", "recruiting", "recruitment", "talent", "hr", "hiring",
    "global", "international", "asia", "apac", "hk", "hong", "kong",
    "limited", "ltd", "inc", "corp", "corporation", "company",
    "graduate", "analyst", "engineer", "program", "programme"
}

ATS_DOMAINS = {
    "workday.com", "myworkday.com", "greenhouse.io", "greenhouse-mail.io",
    "lever.co", "hire.lever.co", "tal.net", "brassring.com",
    "hackerrankforwork.com", "hirevue.com", "hirevue-app.eu"
}

# =========================
# FROM SECONDFILTER.PY
# =========================
SKIP_PATTERNS = [
    r"zendesk\.com",
    r"Ticket\s*#\d+",
    r"We are waiting for your response",
    r"theforage\.com.*Build skills",
    r"Your Cluely Digest",
    r"Latest.*jobs.*in",
    r"New jobs for:",
    r"Welcome to .* Office$",
    r"Event Reminder",
    r"Your registration for Virtual",
    r"days left to complete",
    r"credly\.com",
]

STAGE_PATTERNS = {
    "application_submitted": [
        r"thank you for (applying|your application)",
        r"we've received your application",
        r"application (received|submitted)",
        r"thanks for applying",
    ],
    "aptitude_test": [
        r"plum",
        r"pymetrics",
        r"shl\.com",
        r"talent.*assessment",
        r"psychometric",
        r"behavioral.*assessment",
        r"personality.*assessment",
    ],
    "simulation_test": [
        r"simulate",
        r"simulation",
        r"forage",
        r"job.*preview",
        r"situational.*judgment|sjt",
    ],
    "coding_test": [
        r"hackerrank",
        r"codesignal",
        r"codility",
        r"coding.*(test|assessment|challenge)",
        r"technical.*assessment",
        r"take.*home.*assignment",
    ],
    "video_interview": [
        r"hirevue",
        r"willo",
        r"pre-recorded.*video",
        r"one-way.*video",
        r"record your (answer|response)",
    ],
    "human_interview": [
        r"interview.*(scheduled|confirmation|invitation)",
        r"assessment centre",
        r"super day",
        r"meet with",
        r"speak with you",
    ],
    "rejection": [
        r"not.*(proceed|move forward|moving forward)",
        r"unfortunately",
        r"will not be",
        r"decided not to proceed",
        r"regret to inform",
    ],
    "offer": [
        r"(pleased|delighted) to offer",
        r"offer letter",
        r"congratulations.*offer",
    ],
}

BAD_POSITION_PATTERNS = [
    "job title", "actual job title", "empty string", "role at",
    "thank you for", "we've received", "we have received",
    "your application", "application received"
]


# =========================
# HELPER FUNCTIONS
# =========================
def extract_json(text):
    """Extract JSON from GPT response (from secondfilter.py)"""
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except:
            pass

    start = text.find("{")
    if start == -1:
        return {}

    depth = 0
    for i, char in enumerate(text[start:], start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i+1])
                except:
                    break
    return {}


def clean_domain(email):
    """Extract domain from email address (from firstfilter.py)"""
    if not email:
        return ""
    s = email.strip()
    if "<" in s and ">" in s:
        s = s.split("<", 1)[1].split(">", 1)[0]
    if "@" in s:
        s = s.split("@", 1)[1]
    return s.lower().strip(">").strip('"').strip("'")


def parse_date(date_str):
    """Normalize date to YYYY-MM-DD format (from secondfilter.py)"""
    if not date_str:
        return None

    # ISO format: 2025-10-02T03:43:14+00:00
    match = re.search(r"(\d{4}-\d{2}-\d{2})", date_str)
    if match:
        return match.group(1)

    # RFC format: Mon, 03 Nov 2025 21:43:20 +0000
    try:
        from datetime import datetime
        # Remove timezone info for parsing
        clean = re.sub(r'\s*\([^)]*\)\s*$', '', date_str)  # Remove (UTC) etc
        clean = re.sub(r'\s*[+-]\d{4}\s*$', '', clean)     # Remove +0000 etc
        clean = clean.strip()

        for fmt in [
            "%a, %d %b %Y %H:%M:%S",
            "%d %b %Y %H:%M:%S",
        ]:
            try:
                dt = datetime.strptime(clean, fmt)
                return dt.strftime("%Y-%m-%d")
            except:
                continue
    except:
        pass

    return None


def should_skip(email):
    """Check if email should be skipped (from secondfilter.py)"""
    subject = email.get("subject", "").lower()
    from_email = email.get("from_email", "").lower()
    text = f"{subject} {from_email}"

    for pattern in SKIP_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def detect_stages(email):
    """Pre-detect stages using regex (from secondfilter.py)"""
    subject = email.get("subject", "").lower()
    from_email = email.get("from_email", "").lower()
    body = email.get("body", "").lower()[:500]
    text = f"{subject} {from_email} {body}"

    detected = []
    for stage, patterns in STAGE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                detected.append(stage)
                break
    return detected


def deduplicate_emails(emails):
    """Remove duplicates, keeping rejections separate (from secondfilter.py)"""
    seen = set()
    unique = []
    rejection_phrases = ["regret to inform", "will not be moving forward", "not proceed", "unfortunately"]

    for email in emails:
        subject = email.get("subject", "")
        body = email.get("body", "").lower()[:500]
        normalized = re.sub(r"^(re:|fwd:|fw:)\s*", "", subject.lower(), flags=re.IGNORECASE).strip()
        is_rejection = any(phrase in body for phrase in rejection_phrases)
        key = (normalized[:60], is_rejection)

        if key not in seen:
            seen.add(key)
            unique.append(email)

    return unique


def clean_body_text(body):
    """Clean body text for GPT (from secondfilter.py)"""
    if not body:
        return ""
    text = re.sub(r'\s+', ' ', body).strip()
    text = re.sub(r'(unsubscribe|privacy policy|terms of service|view in browser).*', '', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://\S+', '[link]', text)
    if len(text) > 300:
        text = text[:300] + "..."
    return text


def format_compact(emails):
    """Format emails for GPT with body (from secondfilter.py)"""
    lines = []
    for e in emails:
        date = parse_date(e.get("date", "")) or "?"
        subject = e.get("subject", "")[:80]
        from_email = e.get("from_email", "")
        domain_match = re.search(r"@([^>\s]+)", from_email)
        domain = domain_match.group(1)[:25] if domain_match else "?"
        stages = detect_stages(e)
        stage_str = f" [{','.join(stages)}]" if stages else ""
        body = clean_body_text(e.get("body", ""))
        body_str = f"\n   Body: {body}" if body else ""
        lines.append(f"{date} | {domain} | {subject}{stage_str}{body_str}")
    return "\n".join(lines)


def build_strict_query(company, all_messages, date_filter=""):
    """
    Build a STRICT Gmail query for a company (from firstfilter.py).
    Key improvements:
    1. Only use meaningful tokens (filter out generic ones)
    2. Prioritize exact company name matches
    3. Use domain matching only for company-specific domains
    """
    company_lower = company.lower().strip()

    # Tokenize company name
    raw_tokens = re.split(r"[\s,\-_/&.]+", company_lower)
    tokens = [t for t in raw_tokens if t and len(t) > 1]

    # Filter out generic tokens
    meaningful_tokens = [t for t in tokens if t not in GENERIC_TOKENS]

    # If no meaningful tokens left, use full company name only
    if not meaningful_tokens:
        meaningful_tokens = [company_lower.replace(" ", "")]

    query_parts = []

    # 1) EXACT subject match (highest priority)
    query_parts.append(f'subject:"{company}"')

    # 2) Subject with meaningful tokens (AND not OR for multiple tokens)
    if len(meaningful_tokens) >= 2:
        token_query = " ".join([f"subject:{t}" for t in meaningful_tokens[:2]])
        query_parts.append(f"({token_query})")
    elif meaningful_tokens:
        query_parts.append(f"subject:{meaningful_tokens[0]}")

    # 3) Domain-based matching (only for company-specific domains)
    company_domains = set()
    for m in all_messages:
        fe = m.get("from_email", "").lower()
        if "@" in fe:
            domain = fe.split("@")[-1].split(">")[0].strip()
            is_ats = any(ats in domain for ats in ["workday", "greenhouse", "lever", "brassring", "hirevue", "hackerrank"])
            if not is_ats:
                for token in meaningful_tokens:
                    if token in domain and len(token) >= 3:
                        company_domains.add(domain)
                        break

    if company_domains:
        domain_query = " OR ".join([f"from:{d}" for d in company_domains])
        query_parts.append(f"({domain_query})")

    # 4) HackerRank/Codility emails with company name in subject
    query_parts.append(f'(from:hackerrankforwork.com subject:"{company}")')
    query_parts.append(f'(from:codility.com subject:"{company}")')

    # Combine with OR
    combined = " OR ".join(query_parts)

    # Add date filter and inbox
    final_query = f"({combined}) in:inbox{date_filter}"

    return final_query


def validate_emails_for_company(company, emails):
    """Filter emails to only include those for this company (from firstfilter.py)"""
    company_lower = company.lower()
    tokens = re.split(r"[\s,\-_/&.]+", company_lower)
    meaningful_tokens = [t for t in tokens if t and t not in GENERIC_TOKENS and len(t) > 2]

    validated = []
    for email in emails:
        subject = email.get("subject", "").lower()
        from_email = email.get("from_email", "").lower()
        body = email.get("body", "").lower()[:1000]

        subject_match = company_lower in subject or any(t in subject for t in meaningful_tokens if len(t) >= 4)
        domain = clean_domain(from_email)
        domain_match = any(t in domain for t in meaningful_tokens if len(t) >= 3)
        body_match = company_lower in body or any(t in body for t in meaningful_tokens if len(t) >= 4)

        is_ats = any(ats in domain for ats in ["workday", "greenhouse", "lever", "brassring", "hirevue", "hackerrank", "tal.net"])
        if is_ats:
            if subject_match or body_match:
                validated.append(email)
        elif subject_match or domain_match:
            validated.append(email)

    return validated


def fetch_emails_from_render(query, max_loops=10):
    """Fetch emails from Render with pagination (from firstfilter.py)"""
    all_msgs = []
    next_page = None

    for _ in range(max_loops):
        url = f"{RENDER_URL}/query"
        params = {"q": query, "format": "full"}
        if next_page:
            params["page_token"] = next_page

        print(f"  Fetching: {url}")
        resp = requests.get(url, params=params, timeout=60)
        if resp.status_code != 200:
            print(f"  Error: {resp.status_code}")
            break

        data = resp.json()
        msgs = data.get("messages", [])
        all_msgs.extend(msgs)

        next_page = data.get("next_page_token")
        if not next_page:
            break

    return all_msgs


# =========================
# ROUTES
# =========================
@app.route('/')
def index():
    return jsonify({
        "status": "Local processing server running",
        "endpoints": [
            "/process - Process emails (cached for 24h)",
            "/process?refresh=true - Bypass cache",
            "/status - Check auth status",
            "/cache-info - View cache entries",
            "/clear-cache - Clear all cache"
        ]
    })


@app.route('/status')
def status():
    """Proxy to Render's status endpoint"""
    try:
        resp = requests.get(f"{RENDER_URL}/status")
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"authenticated": False, "error": str(e)})


@app.route('/clear-cache')
def clear_cache():
    """Clear the entire cache"""
    try:
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
            return jsonify({"success": True, "message": "Cache cleared"})
        return jsonify({"success": True, "message": "Cache was already empty"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/cache-info')
def cache_info():
    """Get information about cached entries"""
    cache = load_cache()
    entries = []
    current_time = time.time()

    for key, entry in cache.items():
        cached_time = entry.get("timestamp", 0)
        age_hours = (current_time - cached_time) / 3600
        remaining_hours = max(0, 24 - age_hours)
        entries.append({
            "start_date": entry.get("start_date"),
            "end_date": entry.get("end_date"),
            "age_hours": round(age_hours, 1),
            "expires_in_hours": round(remaining_hours, 1),
            "companies": entry.get("data", {}).get("total_companies", 0)
        })

    return jsonify({
        "total_entries": len(entries),
        "entries": entries
    })


@app.route('/process')
def process():
    """
    Main endpoint using EXACT logic from firstfilter.py + secondfilter.py
    Accepts optional query parameters:
    - start_date: YYYY-MM-DD format
    - end_date: YYYY-MM-DD format
    - refresh: set to 'true' to bypass cache
    """
    # Get date parameters from query string
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    force_refresh = request.args.get('refresh', '').lower() == 'true'

    # Get user email for per-user caching
    user_email = get_user_email()

    print(f"\n{'='*60}")
    print(f"📥 /process REQUEST")
    print(f"   user: '{user_email}'")
    print(f"   start_date: '{start_date}'")
    print(f"   end_date: '{end_date}'")
    print(f"   refresh: {force_refresh}")
    print(f"{'='*60}")

    # Check cache first (unless force refresh)
    if not force_refresh:
        cached = get_cached_result(user_email, start_date, end_date)
        if cached:
            # Add flag to indicate this is cached data
            cached["from_cache"] = True
            return jsonify(cached)

    # Check auth
    try:
        auth_resp = requests.get(f"{RENDER_URL}/status")
        if not auth_resp.json().get("authenticated"):
            return jsonify({"error": "Not authenticated on Render", "authenticated": False}), 401
    except Exception as e:
        return jsonify({"error": f"Cannot reach Render: {e}"}), 500

    try:
        # =========================
        # STEP 1: FIRSTFILTER LOGIC
        # =========================
        print("\n" + "=" * 60)
        print("  FIRSTFILTER: Fetching emails and extracting companies")
        print("=" * 60)

        # Build date filter for Gmail query
        date_filter = ""
        if start_date:
            # Convert YYYY-MM-DD to YYYY/MM/DD for Gmail
            date_filter += f" after:{start_date.replace('-', '/')}"
        if end_date:
            date_filter += f" before:{end_date.replace('-', '/')}"

        # Default to last 6 months if no dates provided
        if not date_filter:
            date_filter = " after:2025/06/06"

        # Fetch all job-related emails
        query = f'subject:("application" OR "applying" OR "apply" OR "applied") in:inbox{date_filter}'
        print(f"\nDate range: {start_date or 'default'} to {end_date or 'now'}")
        print(f"Query: {query}")

        all_emails = fetch_emails_from_render(query)
        print(f"Total emails fetched: {len(all_emails)}")

        if not all_emails:
            return jsonify({"companies": [], "total_companies": 0, "total_applications": 0})

        # Deduplicate for GPT company extraction
        seen, slim = set(), []
        for m in all_emails:
            fe = (m.get("from_email") or "").strip()
            sj = (m.get("subject") or "").strip()
            key = (fe.lower(), sj.lower())
            if fe and sj and key not in seen:
                seen.add(key)
                slim.append({"from_email": fe, "subject": sj})

        print(f"Unique emails for company extraction: {len(slim)}")

        # Build GPT prompt for company extraction (from firstfilter.py)
        lines = []
        for m in slim[:100]:
            dom = clean_domain(m["from_email"])
            subj = m["subject"][:160]
            lines.append(f"{dom} | {subj}")

        company_prompt = f"""Below are job-related emails as 'from_domain | subject'.
Extract the REAL company names the user applied to.

IMPORTANT:
- ATS domains (lever.co, workday.com, greenhouse.io, tal.net) are NOT companies.
  Extract the real company from the SUBJECT.
- Examples:
  - "hire.lever.co | Thank you for application to ION Group" → "ION Group"
  - "blackrock.tal.net | BlackRock | Application update" → "BlackRock"
  - "myworkday.com | Thank You for Applying to MUFG" → "MUFG"
  - "noreply@mail.hirevue-app.eu | Video interview for UBS" → "UBS"

Return JSON: {{"companies_applied":["Company1","Company2",...]}}

Emails:
```
{chr(10).join(lines)}
```"""

        print("\nExtracting companies with GPT...")
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You extract company names from job application emails."},
                {"role": "user", "content": company_prompt}
            ]
        )

        companies_raw = extract_json(response.choices[0].message.content or "").get("companies_applied", [])
        print(f"First extraction: {companies_raw}")

        # Clean company names with second GPT call (from firstfilter.py)
        clean_prompt = f"""Clean this list of company names:

1. REMOVE non-companies: "BAE", "KIM", "WORKDAY", "GREENHOUSE", "LEVER", generic names
2. NORMALIZE: "Morgan Stanley HK" → "Morgan Stanley", "Bloomberg L.P." → "Bloomberg"
3. MERGE duplicates
4. IMPORTANT: Keep "UBS" and "ION Group" as SEPARATE companies (they are different!)

Input: {companies_raw}
Output JSON: {{"clean_companies": ["Company1", "Company2", ...]}}"""

        print("\nCleaning company names...")
        resp2 = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You clean and deduplicate company names."},
                {"role": "user", "content": clean_prompt}
            ]
        )

        companies = extract_json(resp2.choices[0].message.content or "").get("clean_companies", companies_raw)
        print(f"Final companies: {companies}")

        # =========================
        # STEP 2: SECONDFILTER LOGIC (per company)
        # =========================
        print("\n" + "=" * 60)
        print("  SECONDFILTER: Analyzing each company")
        print("=" * 60)

        results = []

        for company in companies[:15]:  # Limit to 15 companies
            print(f"\n--- {company.upper()} ---")

            # Build strict query for this company (like firstfilter.py)
            company_query = build_strict_query(company, all_emails, date_filter)
            print(f"  Query: {company_query[:80]}...")

            # Fetch emails specifically for this company
            company_raw_emails = fetch_emails_from_render(company_query)
            print(f"  Fetched: {len(company_raw_emails)}")

            # Validate emails belong to this company
            company_emails = validate_emails_for_company(company, company_raw_emails)
            print(f"  Validated: {len(company_emails)}")

            if not company_emails:
                continue

            # Filter noise
            filtered = [e for e in company_emails if not should_skip(e)]
            print(f"  After noise filter: {len(filtered)}")

            # Sort by date
            filtered.sort(key=lambda x: parse_date(x.get("date", "")) or "9999")

            # Deduplicate (keeping rejections separate)
            unique = deduplicate_emails(filtered)
            print(f"  After dedup: {len(unique)}")

            if not unique:
                continue

            # Pre-detect stages
            pre_detected = {
                "application_submitted": None,
                "aptitude_test": None,
                "simulation_test": None,
                "coding_test": None,
                "video_interview": None,
                "human_interview_dates": [],
                "rejection": None,
                "offer": None,
            }

            for email in unique:
                date = parse_date(email.get("date", ""))
                stages = detect_stages(email)
                for stage in stages:
                    if stage == "human_interview":
                        if date and date not in pre_detected["human_interview_dates"]:
                            pre_detected["human_interview_dates"].append(date)
                    elif stage in pre_detected:
                        if date and pre_detected[stage] is None:
                            pre_detected[stage] = date

            # Print pre-detected stages (like secondfilter.py)
            print(f"  Pre-detected: {json.dumps({k:v for k,v in pre_detected.items() if v}, indent=2)}")

            # Format emails for GPT
            compact_text = format_compact(unique[:15])  # Limit for token efficiency

            # Build pre-detected hints
            pre_detected_hints = []
            if pre_detected["rejection"]:
                pre_detected_hints.append(f"REJECTION detected on {pre_detected['rejection']}")
            if pre_detected["offer"]:
                pre_detected_hints.append(f"OFFER detected on {pre_detected['offer']}")
            pre_hint_str = "\n".join(pre_detected_hints) if pre_detected_hints else ""

            # Build analysis prompt (from secondfilter.py - EXACT)
            analysis_prompt = f"""Analyze job application emails for "{company}".

EMAILS (date | sender | subject [pre-detected stages]):
{compact_text}

{f"PRE-DETECTED STATUS: {pre_hint_str}" if pre_hint_str else ""}

CRITICAL RULES:
1. POSITION: Extract the actual JOB TITLE (e.g., "Graduate Software Engineer", "Analyst Program 2026", "Data Scientist").
   - Look for patterns like "applying for [POSITION]", "application for [POSITION]", "Thank you for applying to [POSITION]"
   - NEVER use generic phrases like "Thank you for your application", "We've received your application", "role at X"

2. MULTIPLE POSITIONS: If the candidate applied to MULTIPLE different positions at this company, return ALL of them as separate entries in the "positions" array. Each position should have its own timeline and status.

3. "video_interview" = ONE-WAY pre-recorded video (HireVue, Willo) only. Phone calls and live video calls are human_interviews.

4. Count human interviews: same event on same day = 1, different days = multiple. "Super Day" = 1 event.

5. "status": For EACH position separately - "rejected" if that specific position was rejected, "offer" if offered, "pending" otherwise.

OUTPUT JSON only (array of positions):
{{"positions":[{{"position":"Job Title","applied":"YYYY-MM-DD","aptitude_test":"YYYY-MM-DD or null","simulation_test":"YYYY-MM-DD or null","coding_test":"YYYY-MM-DD or null","video_interview":"YYYY-MM-DD or null","human_interviews":N,"status":"pending|rejected|offer"}}]}}"""

            try:
                print(f"  Calling GPT for analysis...")
                analysis = client.chat.completions.create(
                    model=MODEL,
                    messages=[
                        {"role": "system", "content": "You are a precise job application timeline extractor. Output valid JSON only."},
                        {"role": "user", "content": analysis_prompt}
                    ],
                    temperature=0.1
                )

                result = extract_json(analysis.choices[0].message.content or "")
                positions = result.get("positions", [])

                # Handle legacy single-position format
                if not positions and result.get("position"):
                    positions = [result]

                if not positions:
                    continue

                # Clean up positions (from secondfilter.py)
                final_positions = []
                for i, pos in enumerate(positions):
                    position_name = pos.get("position", "")
                    if any(bad in position_name.lower() for bad in BAD_POSITION_PATTERNS):
                        position_name = ""

                    use_predetected = (i == 0)

                    final_pos = {
                        "position": position_name,
                        "application_submitted": pos.get("applied") or (pre_detected["application_submitted"] if use_predetected else None),
                        "aptitude_test": pos.get("aptitude_test") if pos.get("aptitude_test") not in [None, "null", ""] else (pre_detected["aptitude_test"] if use_predetected else None),
                        "simulation_test": pos.get("simulation_test") if pos.get("simulation_test") not in [None, "null", ""] else (pre_detected["simulation_test"] if use_predetected else None),
                        "coding_test": pos.get("coding_test") if pos.get("coding_test") not in [None, "null", ""] else (pre_detected["coding_test"] if use_predetected else None),
                        "video_interview": pos.get("video_interview") if pos.get("video_interview") not in [None, "null", ""] else (pre_detected["video_interview"] if use_predetected else None),
                        "num_human_interview": str(pos.get("human_interviews", 0) or (len(pre_detected["human_interview_dates"]) if use_predetected else 0)),
                        "app_accepted": (
                            "y" if pos.get("status") == "offer" else
                            ("n" if pos.get("status") == "rejected" else None)
                        )
                    }

                    # Clean null strings
                    for key in final_pos:
                        if final_pos[key] == "null":
                            final_pos[key] = None

                    final_positions.append(final_pos)

                if final_positions:
                    results.append({
                        "name": company,
                        "positions": final_positions,
                        "email_count": len(company_emails)
                    })
                    print(f"  ✅ {len(final_positions)} position(s) found")

            except Exception as e:
                print(f"  ❌ Error: {e}")
                continue

        # Calculate totals
        total_applications = sum(len(c["positions"]) for c in results)

        print("\n" + "=" * 60)
        print(f"  DONE! {len(results)} companies, {total_applications} applications")
        print("=" * 60)

        # Prepare response data
        response_data = {
            "companies": results,
            "total_companies": len(results),
            "total_applications": total_applications,
            "from_cache": False
        }

        # Cache the result (without the from_cache flag)
        cache_data = {
            "companies": results,
            "total_companies": len(results),
            "total_applications": total_applications
        }
        set_cached_result(user_email, start_date, end_date, cache_data)

        return jsonify(response_data)

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("  Local Processing Server for JobTracker AI")
    print("  Using EXACT logic from firstfilter.py + secondfilter.py")
    print("=" * 60)
    print("Make sure you're authenticated on Render first!")
    print("")
    print("Starting on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5001, debug=True)

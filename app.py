import os
import re
import base64
import json
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from datetime import datetime
from openai import AzureOpenAI

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# Allow OAuth without https during local dev (Render uses https automatically)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# GMAIL SETTINGS
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# =========================
# Load secrets from environment variables
# =========================
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")

# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "https://api-iw.azure-api.net/sig-shared-jpeast/deployments/gpt-4o-mini/chat/completions?api-version=2025-01-01-preview")
AZURE_OPENAI_KEY = os.environ.get("AZURE_OPENAI_KEY", "72fc700a6bd24963b8e4cf5d28d4e95c")
AZURE_OPENAI_MODEL = "gpt-4o-mini"

# Initialize Azure OpenAI client
openai_client = AzureOpenAI(
    azure_endpoint=AZURE_OPENAI_ENDPOINT,
    api_key=AZURE_OPENAI_KEY,
    api_version="2025-01-01-preview"
)

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not REDIRECT_URI:
    raise RuntimeError("Missing Google OAuth environment variables.")

CLIENT_CONFIG = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "project_id": "render-deployed-app",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uris": [REDIRECT_URI]
    }
}

TOKEN_FILE = "/opt/render/project/token.json"

# =========================
# GENERIC TOKENS TO EXCLUDE
# =========================
GENERIC_TOKENS = {
    "group", "teams", "page", "career", "careers", "jobs", "job",
    "recruit", "recruiting", "recruitment", "talent", "hr", "hiring",
    "global", "international", "asia", "apac", "hk", "hong", "kong",
    "limited", "ltd", "inc", "corp", "corporation", "company",
    "graduate", "analyst", "engineer", "program", "programme"
}

# =========================
# STAGE DETECTION PATTERNS
# =========================
STAGE_PATTERNS = {
    "application_submitted": [
        r"thank you for (applying|your application|your interest)",
        r"application (received|submitted|confirmed)",
        r"we('ve| have) received your application",
    ],
    "aptitude_test": [
        r"plum", r"pymetrics", r"shl\.com", r"talent\s*q",
        r"cognitive\s*(test|assessment)", r"personality\s*(test|assessment)",
        r"wonderlic", r"criteria\s*corp",
    ],
    "simulation_test": [
        r"forage", r"theforage\.com", r"job\s*simulation",
        r"virtual\s*(experience|internship)", r"situational\s*judgement",
    ],
    "coding_test": [
        r"hackerrank", r"codility", r"codesignal", r"leetcode",
        r"coding\s*(test|challenge|assessment)", r"technical\s*assessment",
        r"online\s*(test|assessment).*code",
    ],
    "video_interview": [
        r"hirevue", r"willo", r"spark\s*hire", r"vidcruiter",
        r"pre-recorded\s*video", r"video\s*interview\s*invitation",
        r"record.*video.*response",
    ],
    "human_interview": [
        r"interview\s*(scheduled|confirmed|invitation)",
        r"meet\s*with", r"speak\s*with", r"call\s*with",
        r"phone\s*(screen|interview)", r"final\s*round",
        r"on-?site", r"assessment\s*centre", r"superday",
    ],
    "rejection": [
        r"not.*(proceed|move forward|moving forward)",
        r"unfortunately",
        r"will not be",
        r"decided not to proceed",
        r"regret to inform",
    ],
    "offer": [
        r"(pleased|happy|excited) to offer",
        r"offer\s*(letter|of employment)",
        r"congratulations.*offer",
    ],
}


# =========================
# HELPER FUNCTIONS
# =========================
def extract_body_recursive(payload, prefer_html=False):
    """Recursively parse Gmail message payload to extract body content."""
    mime_type = payload.get('mimeType', '')

    if mime_type == 'text/plain':
        body_data = payload.get('body', {}).get('data')
        if body_data:
            return base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

    if mime_type == 'text/html' and prefer_html:
        body_data = payload.get('body', {}).get('data')
        if body_data:
            html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
            text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
            text = re.sub(r'<[^>]+>', ' ', text)
            text = re.sub(r'\s+', ' ', text).strip()
            return text

    if 'parts' in payload:
        plain_text = None
        html_text = None

        for part in payload['parts']:
            part_mime = part.get('mimeType', '')

            if part.get('filename'):
                continue

            if part_mime.startswith('multipart/'):
                result = extract_body_recursive(part, prefer_html)
                if result:
                    return result

            elif part_mime == 'text/plain':
                body_data = part.get('body', {}).get('data')
                if body_data:
                    plain_text = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

            elif part_mime == 'text/html':
                body_data = part.get('body', {}).get('data')
                if body_data:
                    html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                    text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
                    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
                    text = re.sub(r'<[^>]+>', ' ', text)
                    text = re.sub(r'\s+', ' ', text).strip()
                    html_text = text

        if plain_text:
            return plain_text
        if html_text:
            return html_text

    body_data = payload.get('body', {}).get('data')
    if body_data:
        return base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

    return ""


def extract_json(text):
    """Extract JSON from GPT response."""
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except:
            pass

    start = text.find("{")
    while start != -1:
        depth = 0
        i = start
        in_str = False
        esc = False
        while i < len(text):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i+1])
                        except:
                            break
            i += 1
        start = text.find("{", start + 1)
    return {}


def parse_date(date_str):
    """Extract YYYY-MM-DD from various date formats."""
    if not date_str:
        return None
    match = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
    if match:
        return match.group(1)
    return None


def clean_domain(email):
    """Extract domain from email address."""
    if not email:
        return ""
    s = email.strip()
    if "<" in s and ">" in s:
        s = s.split("<", 1)[1].split(">", 1)[0]
    if "@" in s:
        s = s.split("@", 1)[1]
    return s.lower().strip(">").strip('"').strip("'")


def detect_stages(email):
    """Pre-detect stages using regex patterns."""
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


def fetch_all_emails(service, query, max_results=200):
    """Fetch emails with pagination."""
    all_msgs = []
    page_token = None

    while len(all_msgs) < max_results:
        list_params = {'userId': 'me', 'q': query, 'maxResults': 50}
        if page_token:
            list_params['pageToken'] = page_token

        resp = service.users().messages().list(**list_params).execute()
        messages = resp.get('messages', [])

        for msg in messages:
            if len(all_msgs) >= max_results:
                break
            msg_data = service.users().messages().get(
                userId='me', id=msg['id'], format='full'
            ).execute()

            headers = msg_data.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
            from_email = next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown Sender)')
            date_raw = next((h['value'] for h in headers if h['name'] == 'Date'), None)

            try:
                date_obj = datetime.strptime(date_raw, "%a, %d %b %Y %H:%M:%S %z")
                date_iso = date_obj.isoformat()
            except:
                date_iso = date_raw or ""

            payload = msg_data.get('payload', {})
            body_text = extract_body_recursive(payload)

            all_msgs.append({
                "subject": subject,
                "date": date_iso,
                "from_email": from_email,
                "body": body_text[:2000]
            })

        page_token = resp.get('nextPageToken')
        if not page_token:
            break

    return all_msgs


# =========================
# ROUTES
# =========================
@app.route('/')
def index():
    if os.path.exists(TOKEN_FILE):
        return '<p>Already authenticated! Use /query?q=... or /process</p>'

    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
    return redirect(auth_url)


@app.route('/callback')
def callback():
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    with open(TOKEN_FILE, 'w') as token:
        token.write(creds.to_json())

    return """
<script>
  if (window.opener) {
    window.opener.postMessage({ status: "success", authenticated: true }, "*");
  }
  window.close();
</script>
"""


@app.route('/status')
def status():
    """Check authentication status."""
    authenticated = os.path.exists(TOKEN_FILE)
    return jsonify({"authenticated": authenticated})


@app.route('/user-info')
def user_info():
    """Get authenticated user's Gmail profile info."""
    if not os.path.exists(TOKEN_FILE):
        return jsonify({"error": "Not authenticated", "authenticated": False}), 401

    try:
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()

        return jsonify({
            "email": profile.get("emailAddress", ""),
            "messagesTotal": profile.get("messagesTotal", 0),
            "threadsTotal": profile.get("threadsTotal", 0)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/logout')
def logout():
    """Clear authentication and log out."""
    try:
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
        return jsonify({"success": True, "message": "Logged out successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/query')
def query():
    q = request.args.get('q', 'in:inbox')
    page_token = request.args.get('page_token', None)

    if not os.path.exists(TOKEN_FILE):
        return jsonify({"error": "Not authenticated", "authenticated": False}), 401

    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    service = build('gmail', 'v1', credentials=creds)

    list_params = {'userId': 'me', 'q': q, 'maxResults': 50}
    if page_token:
        list_params['pageToken'] = page_token

    resp = service.users().messages().list(**list_params).execute()
    messages = resp.get('messages', [])
    next_page_token = resp.get('nextPageToken', None)
    results = []

    for msg in messages:
        msg_data = service.users().messages().get(
            userId='me', id=msg['id'], format='full'
        ).execute()

        headers = msg_data.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
        from_email = next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown Sender)')
        date_raw = next((h['value'] for h in headers if h['name'] == 'Date'), None)

        try:
            date_obj = datetime.strptime(date_raw, "%a, %d %b %Y %H:%M:%S %z")
            date_iso = date_obj.isoformat()
        except:
            date_iso = date_raw or ""

        payload = msg_data.get('payload', {})
        body_text = extract_body_recursive(payload)

        results.append({
            "subject": subject,
            "date": date_iso,
            "from_email": from_email,
            "body": body_text[:2000]
        })

    response_data = {
        "query": q,
        "total_results": len(results),
        "messages": results
    }

    if next_page_token:
        response_data["next_page_token"] = next_page_token

    return jsonify(response_data)


@app.route('/process')
def process():
    """
    Main endpoint: Fetch emails, extract companies, analyze applications.
    Returns structured application data for all companies.
    """
    if not os.path.exists(TOKEN_FILE):
        return jsonify({"error": "Not authenticated", "authenticated": False}), 401

    try:
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        service = build('gmail', 'v1', credentials=creds)

        # Step 1: Fetch job-related emails
        query = 'subject:("application" OR "applying" OR "apply" OR "applied") in:inbox after:2024/01/01'
        emails = fetch_all_emails(service, query, max_results=200)

        if not emails:
            return jsonify({
                "companies": [],
                "total_companies": 0,
                "total_applications": 0,
                "message": "No job application emails found"
            })

        # Step 2: Deduplicate emails
        seen = set()
        unique_emails = []
        for e in emails:
            key = (e.get("from_email", "").lower(), e.get("subject", "").lower())
            if key not in seen:
                seen.add(key)
                unique_emails.append(e)

        # Step 3: Extract company names using GPT
        lines = []
        for e in unique_emails[:100]:  # Limit for token efficiency
            domain = clean_domain(e.get("from_email", ""))
            subject = e.get("subject", "")[:100]
            lines.append(f"{domain} | {subject}")

        company_prompt = f"""Below are job-related emails as 'from_domain | subject'.
Extract the REAL company names the user applied to.

IMPORTANT:
- ATS domains (lever.co, workday.com, greenhouse.io, tal.net) are NOT companies.
  Extract the real company from the SUBJECT.
- Examples:
  - "hire.lever.co | Thank you for application to ION Group" → "ION Group"
  - "blackrock.tal.net | BlackRock | Application update" → "BlackRock"

Return JSON: {{"companies_applied":["Company1","Company2",...]}}

Emails:
```
{chr(10).join(lines)}
```"""

        response = openai_client.chat.completions.create(
            model=AZURE_OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You extract company names from job application emails."},
                {"role": "user", "content": company_prompt}
            ],
            temperature=0.1
        )

        companies_raw = extract_json(response.choices[0].message.content or "").get("companies_applied", [])

        # Step 4: Process each company
        results = []
        for company in companies_raw[:15]:  # Limit to 15 companies
            company_lower = company.lower()
            tokens = re.split(r"[\s,\-_/&.]+", company_lower)
            meaningful_tokens = [t for t in tokens if t and t not in GENERIC_TOKENS and len(t) > 2]

            # Filter emails for this company
            company_emails = []
            for e in emails:
                subject = e.get("subject", "").lower()
                from_email = e.get("from_email", "").lower()
                body = e.get("body", "").lower()[:500]

                # Check if company name or tokens appear
                if (company_lower in subject or
                    company_lower in from_email or
                    any(t in subject for t in meaningful_tokens if len(t) >= 4) or
                    any(t in clean_domain(from_email) for t in meaningful_tokens if len(t) >= 3)):
                    company_emails.append(e)

            if not company_emails:
                continue

            # Deduplicate company emails (keep rejections separate)
            rejection_phrases = ["regret to inform", "will not be moving forward", "not proceed", "unfortunately"]
            seen_keys = set()
            unique_company_emails = []
            for e in company_emails:
                subject = e.get("subject", "").lower()
                body = e.get("body", "").lower()[:500]
                normalized = re.sub(r"^(re:|fwd:|fw:)\s*", "", subject, flags=re.IGNORECASE).strip()[:60]
                is_rejection = any(phrase in body for phrase in rejection_phrases)
                key = (normalized, is_rejection)
                if key not in seen_keys:
                    seen_keys.add(key)
                    unique_company_emails.append(e)

            # Sort by date
            unique_company_emails.sort(key=lambda x: parse_date(x.get("date", "")) or "9999")

            # Format emails for GPT
            email_lines = []
            for e in unique_company_emails[:10]:  # Limit emails per company
                date = parse_date(e.get("date", "")) or "?"
                subject = e.get("subject", "")[:80]
                body = e.get("body", "")[:200].replace("\n", " ").replace("\r", " ")
                stages = detect_stages(e)
                stage_str = f" [{','.join(stages)}]" if stages else ""
                email_lines.append(f"{date} | {subject}{stage_str}\n   Body: {body}...")

            # Call GPT to analyze company applications
            analysis_prompt = f"""Analyze job application emails for "{company}".

EMAILS:
{chr(10).join(email_lines)}

RULES:
1. Extract ALL positions applied to (may be multiple)
2. For each position, extract timeline and status
3. "video_interview" = ONE-WAY pre-recorded only (HireVue, Willo)
4. "status": "rejected" only if that specific position was rejected

OUTPUT JSON:
{{"positions":[{{"position":"Job Title","applied":"YYYY-MM-DD","aptitude_test":"YYYY-MM-DD or null","simulation_test":"YYYY-MM-DD or null","coding_test":"YYYY-MM-DD or null","video_interview":"YYYY-MM-DD or null","human_interviews":N,"status":"pending|rejected|offer"}}]}}"""

            try:
                analysis_response = openai_client.chat.completions.create(
                    model=AZURE_OPENAI_MODEL,
                    messages=[
                        {"role": "system", "content": "You extract job application timelines. Output valid JSON only."},
                        {"role": "user", "content": analysis_prompt}
                    ],
                    temperature=0.1
                )

                analysis_result = extract_json(analysis_response.choices[0].message.content or "")
                positions = analysis_result.get("positions", [])

                if positions:
                    results.append({
                        "name": company,
                        "positions": [
                            {
                                "position": p.get("position", ""),
                                "application_submitted": p.get("applied"),
                                "aptitude_test": p.get("aptitude_test") if p.get("aptitude_test") not in [None, "null", ""] else None,
                                "simulation_test": p.get("simulation_test") if p.get("simulation_test") not in [None, "null", ""] else None,
                                "coding_test": p.get("coding_test") if p.get("coding_test") not in [None, "null", ""] else None,
                                "video_interview": p.get("video_interview") if p.get("video_interview") not in [None, "null", ""] else None,
                                "num_human_interview": str(p.get("human_interviews", 0)),
                                "app_accepted": "y" if p.get("status") == "offer" else ("n" if p.get("status") == "rejected" else None)
                            }
                            for p in positions
                        ],
                        "email_count": len(company_emails)
                    })
            except Exception as e:
                print(f"Error processing {company}: {e}")
                continue

        # Calculate totals
        total_applications = sum(len(c["positions"]) for c in results)

        return jsonify({
            "companies": results,
            "total_companies": len(results),
            "total_applications": total_applications
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5678))
    app.run(host='0.0.0.0', port=port)

import os
import base64
import json
from flask import Flask, request, jsonify, redirect
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from datetime import datetime

app = Flask(__name__)

# Allow OAuth without https during local dev (Render uses https automatically)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# GMAIL SETTINGS
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# =========================
# Load secrets from environment variables
# =========================
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")   # Must match Render URL `/callback`

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

# =========================
# Render-safe token storage location
# =========================
TOKEN_FILE = "/opt/render/project/token.json"


# =========================
# RECURSIVE BODY EXTRACTION
# =========================
def extract_body_recursive(payload, prefer_html=False):
    """
    Recursively parse Gmail message payload to extract body content.

    Gmail messages can have deeply nested structures like:
    - multipart/mixed
      - multipart/alternative
        - text/plain
        - text/html
      - application/pdf (attachment)

    This function traverses all levels to find text/plain or text/html.

    Args:
        payload: The message payload or a part within it
        prefer_html: If True, prefer HTML over plain text

    Returns:
        Decoded body text (str)
    """
    mime_type = payload.get('mimeType', '')

    # Case 1: Direct text content (no nested parts)
    if mime_type == 'text/plain':
        body_data = payload.get('body', {}).get('data')
        if body_data:
            return base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

    if mime_type == 'text/html' and prefer_html:
        body_data = payload.get('body', {}).get('data')
        if body_data:
            # Strip HTML tags for plain text extraction
            import re
            html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
            # Basic HTML to text conversion
            text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
            text = re.sub(r'<[^>]+>', ' ', text)
            text = re.sub(r'\s+', ' ', text).strip()
            return text

    # Case 2: Multipart - recursively search through parts
    if 'parts' in payload:
        plain_text = None
        html_text = None

        for part in payload['parts']:
            part_mime = part.get('mimeType', '')

            # Skip attachments
            if part.get('filename'):
                continue

            # Recursively extract from nested parts
            if part_mime.startswith('multipart/'):
                result = extract_body_recursive(part, prefer_html)
                if result:
                    return result

            # Direct text/plain
            elif part_mime == 'text/plain':
                body_data = part.get('body', {}).get('data')
                if body_data:
                    plain_text = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

            # Direct text/html (fallback)
            elif part_mime == 'text/html':
                body_data = part.get('body', {}).get('data')
                if body_data:
                    import re
                    html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                    text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
                    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
                    text = re.sub(r'<[^>]+>', ' ', text)
                    text = re.sub(r'\s+', ' ', text).strip()
                    html_text = text

        # Prefer plain text, fallback to HTML
        if plain_text:
            return plain_text
        if html_text:
            return html_text

    # Case 3: Single part with body data (no mimeType specified clearly)
    body_data = payload.get('body', {}).get('data')
    if body_data:
        return base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

    return ""


@app.route('/')
def index():
    if os.path.exists(TOKEN_FILE):
        return '<p>Already authenticated! Use /query?q=...</p>'

    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _ = flow.authorization_url(prompt='consent')
    return f'<a href="{auth_url}">Login with Google</a>'


@app.route('/callback')
def callback():
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    # Save token on Render filesystem
    with open(TOKEN_FILE, 'w') as token:
        token.write(creds.to_json())

    # Tell the frontend "login success" and close popup
    return """
<script>
  // Send message back to opener (your React app)
  if (window.opener) {
    window.opener.postMessage(
    { status: "success", authenticated: true },
    "*"
    );
  }
  // Close the popup window
  window.close();
</script>
"""


@app.route('/query')
def query():
    q = request.args.get('q', 'in:inbox')
    page_token = request.args.get('page_token', None)

    if not os.path.exists(TOKEN_FILE):
        return redirect('/')

    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    service = build('gmail', 'v1', credentials=creds)

    # Support pagination
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
        except Exception:
            date_iso = date_raw or "(Unknown Date)"

        # IMPROVED: Recursive body extraction
        payload = msg_data.get('payload', {})
        body_text = extract_body_recursive(payload)

        results.append({
            "subject": subject,
            "date": date_iso,
            "from_email": from_email,
            "body": body_text[:2000]  # Increased limit for better context
        })

    response_data = {
        "query": q,
        "total_results": len(results),
        "messages": results
    }

    # Include next_page_token if available
    if next_page_token:
        response_data["next_page_token"] = next_page_token

    return jsonify(response_data)


# Render will use Gunicorn, but local dev still ok
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5678)

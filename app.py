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
# 🔐 Load secrets from environment variables
# =========================
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")   # Must match Render URL `/callback`

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not REDIRECT_URI:
    raise RuntimeError("❌ Missing Google OAuth environment variables.")

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
# 📁 Render-safe token storage location
# =========================
TOKEN_FILE = "/opt/render/project/token.json"


@app.route('/')
def index():
    if os.path.exists(TOKEN_FILE):
        return '<p>✅ Already authenticated! Use /query?q=...</p>'

    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _ = flow.authorization_url(prompt='consent')
    return f'<a href="{auth_url}">Login with Google</a>'


@app.route('/callback')
def callback():
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    with open(TOKEN_FILE, 'w') as token:
        token.write(creds.to_json())

    return '<p>✅ Login success! Go to /query?q=your_query</p>'


@app.route('/query')
def query():
    q = request.args.get('q', 'in:inbox after:2024/01/01')

    if not os.path.exists(TOKEN_FILE):
        return redirect('/')

    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    service = build('gmail', 'v1', credentials=creds)

    resp = service.users().messages().list(userId='me', q=q, maxResults=50).execute()
    messages = resp.get('messages', [])
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

        # Decode body text
        body_text = ""
        if 'parts' in msg_data['payload']:
            for part in msg_data['payload']['parts']:
                if part.get('mimeType') == 'text/plain':
                    body_data = part['body'].get('data')
                    if body_data:
                        body_text = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                        break
        else:
            body_data = msg_data['payload']['body'].get('data')
            if body_data:
                body_text = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

        results.append({
            "subject": subject,
            "date": date_iso,
            "from_email": from_email,
            "body": body_text[:1000]
        })

    return jsonify({
        "query": q,
        "total_results": len(results),
        "messages": results
    })


# Render will use Gunicorn, but local dev still ok
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5678)

import os
from flask import Flask, render_template, redirect, url_for, request, session, flash
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import requests
from dotenv import load_dotenv
from models import db, User

load_dotenv()

app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.labels'
]
CLIENT_SECRETS_FILE = 'credentials.json'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful, please login')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    credentials = None
    if 'credentials' in session:
        credentials = Credentials(**session['credentials'])

    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            return redirect(url_for('authorize'))

    service = build('gmail', 'v1', credentials=credentials)
    results = service.users().messages().list(userId='me').execute()
    messages = results.get('messages', [])

    email_list = []
    for message in messages[:10]:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        email_list.append({
            'id': message['id'],
            'snippet': msg['snippet']
        })

    return render_template('index.html', emails=email_list)

@app.route('/email/<email_id>')
def email_detail(email_id):
    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    credentials = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=credentials)
    msg = service.users().messages().get(userId='me', id=email_id).execute()
    
    headers = msg['payload']['headers']
    subject = next(header['value'] for header in headers if header['name'] == 'Subject')
    from_ = next(header['value'] for header in headers if header['name'] == 'From')
    to = next(header['value'] for header in headers if header['name'] == 'To')
    body = ''
    
    if 'parts' in msg['payload']:
        for part in msg['payload']['parts']:
            if part['mimeType'] == 'text/plain':
                body = part['body']['data']
                break
    else:
        body = msg['payload']['body']['data']

    return render_template('email.html', subject=subject, from_=from_, to=to, body=body)

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    session['state'] = state

    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('index'))

@app.route('/revoke')
def revoke():
    if 'credentials' not in session:
        return 'You need to authorize before testing the code to revoke credentials.'

    credentials = Credentials(**session['credentials'])

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
        params={'token': credentials.token},
        headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return 'Credentials successfully revoked.'
    else:
        return 'An error occurred.'

@app.route('/clear')
def clear_credentials():
    if 'credentials' in session:
        del session['credentials']
    return 'Credentials have been cleared.'

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

if __name__ == '__main__':
    app.run(port=5000, debug=True)

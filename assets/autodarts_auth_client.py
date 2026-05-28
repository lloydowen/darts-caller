import json
import threading
import webbrowser
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from time import sleep

import requests
from authlib.integrations.requests_client import OAuth2Session

AUTH_URL    = 'https://api.autodarts.io/auth/v1/oauth/authorize'
TOKEN_URL   = 'https://api.autodarts.io/auth/v1/exchange'
REFRESH_URL = 'https://api.autodarts.io/auth/v1/refresh'
USERINFO_URL = 'https://api.autodarts.io/auth/v1/userinfo'

TOKEN_FILE = Path.home() / '.config' / 'darts-caller' / 'tokens.json'

# Check every 30 seconds; refresh when within 60 seconds of expiry.
TICK = 30
REFRESH_AHEAD_SECS = 60


class _CallbackHandler(BaseHTTPRequestHandler):
    callback_url: str = None

    def do_GET(self):
        _CallbackHandler.callback_url = 'http://127.0.0.1' + self.path
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'<h2>Logged in to Autodarts! You can close this tab.</h2>')

    def log_message(self, *_):
        pass


class AutodartsAuthClient:
    def __init__(self, *, client_id: str, debug: bool = False):
        self.client_id = client_id
        self.debug = debug
        self.access_token: str = None
        self.user_id: str = None
        self._refresh_token: str = None
        self._expires_at: datetime = None
        self._refresh_expires_at: datetime = None
        self._run = True
        self._thread: threading.Thread = None

        self._login()

    # ------------------------------------------------------------------ public

    def start(self):
        self._thread = threading.Thread(target=self._token_loop, name='autodarts-tokenizer', daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        self._run = False
        if self._thread:
            self._thread.join(timeout=5)
        print('autodarts-tokenizer EXIT')

    # ----------------------------------------------------------------- private

    def _login(self):
        saved = self._load_tokens()
        if saved:
            self._apply(saved)
            if self._expires_at and datetime.now() < self._expires_at:
                if self.debug:
                    print('Loaded valid tokens from disk')
                self._fetch_user_id()
                return
            if self._refresh_expires_at and datetime.now() < self._refresh_expires_at:
                if self.debug:
                    print('Refreshing saved tokens')
                try:
                    self._refresh()
                    return
                except Exception:
                    pass  # fall through to browser login

        self._browser_login()

    def _browser_login(self):
        _CallbackHandler.callback_url = None
        server = HTTPServer(('127.0.0.1', 0), _CallbackHandler)
        port = server.server_address[1]
        redirect_uri = f'http://127.0.0.1:{port}/callback'

        session = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            code_challenge_method='S256',
        )
        url, _ = session.create_authorization_url(AUTH_URL)

        print('Opening browser for Autodarts login…')
        webbrowser.open(url)
        server.handle_request()
        server.server_close()

        token = session.fetch_token(TOKEN_URL, authorization_response=_CallbackHandler.callback_url)
        self._apply(token)
        self._save_tokens()
        self._fetch_user_id()

    def _refresh(self):
        resp = requests.post(REFRESH_URL, json={
            'refresh_token': self._refresh_token,
            'client_id': self.client_id,
        })
        resp.raise_for_status()
        self._apply(resp.json())
        self._save_tokens()
        if self.debug:
            print('Token refreshed, expires', self._expires_at)

    def _fetch_user_id(self):
        resp = requests.get(USERINFO_URL, headers={'Authorization': f'Bearer {self.access_token}'})
        resp.raise_for_status()
        self.user_id = resp.json()['sub']

    def _apply(self, token: dict):
        self.access_token = token['access_token']
        if token.get('refresh_token'):
            self._refresh_token = token['refresh_token']

        if 'expires_at' in token:
            self._expires_at = datetime.fromtimestamp(float(token['expires_at']))
        elif 'expires_in' in token:
            self._expires_at = datetime.now() + timedelta(seconds=int(token['expires_in']))

        # Refresh token lifetime is 30 days per Autodarts API spec.
        self._refresh_expires_at = datetime.now() + timedelta(days=30)

    def _save_tokens(self):
        try:
            TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(TOKEN_FILE, 'w') as f:
                json.dump({
                    'access_token': self.access_token,
                    'refresh_token': self._refresh_token,
                    'expires_at': self._expires_at.timestamp() if self._expires_at else None,
                }, f)
        except Exception:
            pass

    def _load_tokens(self) -> dict | None:
        try:
            if TOKEN_FILE.exists():
                with open(TOKEN_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def _token_loop(self):
        while self._run:
            sleep(TICK)
            try:
                if self.access_token is None:
                    self._browser_login()
                    continue

                now = datetime.now()
                if self._expires_at and (self._expires_at - now).total_seconds() < REFRESH_AHEAD_SECS:
                    if self._refresh_expires_at and now < self._refresh_expires_at:
                        self._refresh()
                    else:
                        print('Refresh token expired — re-authenticating via browser')
                        self._browser_login()
            except Exception:
                self.access_token = None
                print('Token refresh failed')

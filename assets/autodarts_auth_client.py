import json
import os
import threading
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

import requests

AUTH_BASE = os.getenv('AUTODARTS_AUTH_URL', 'https://api.autodarts.io/auth/v1/').rstrip('/')
DEVICE_CODE_URL = f'{AUTH_BASE}/device/code'
DEVICE_TOKEN_URL = f'{AUTH_BASE}/device/token'
REFRESH_URL = f'{AUTH_BASE}/refresh'
USERINFO_URL = f'{AUTH_BASE}/userinfo'

DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'

VERIFY_TLS = os.getenv('AUTODARTS_AUTH_INSECURE_TLS', '').lower() not in ('1', 'true', 'yes')

TOKEN_FILE = Path.home() / '.config' / 'darts-caller' / 'tokens.json'

TICK = 30
REFRESH_AHEAD_SECS = 60


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
        env_access = os.getenv('AUTODARTS_ACCESS_TOKEN')
        env_refresh = os.getenv('AUTODARTS_REFRESH_TOKEN')
        if env_access and env_refresh:
            if self.debug:
                print('Using tokens from environment variables')
            self._apply({'access_token': env_access, 'refresh_token': env_refresh})
            self._fetch_user_id()
            return

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
                    pass

        self._device_login()

    def _device_login(self):
        resp = requests.post(DEVICE_CODE_URL, json={'client_id': self.client_id}, verify=VERIFY_TLS)
        resp.raise_for_status()
        data = resp.json()

        device_code = data['device_code']
        user_code = data['user_code']
        verification_uri = data['verification_uri']
        verification_uri_complete = data.get('verification_uri_complete')
        interval = int(data.get('interval', 5))
        expires_in = int(data.get('expires_in', 600))

        print('\n' + '=' * 60)
        print('Connect darts-caller to your Autodarts account:')
        print(f'  1. Open {verification_uri}')
        print(f'  2. Enter the code:  {user_code}')
        if verification_uri_complete:
            print(f'\nOr open this link directly:\n  {verification_uri_complete}')
        print('=' * 60 + '\n')

        if verification_uri_complete:
            try:
                webbrowser.open(verification_uri_complete)
            except Exception:
                pass

        deadline = datetime.now() + timedelta(seconds=expires_in)
        while self._run and datetime.now() < deadline:
            sleep(interval)
            resp = requests.post(DEVICE_TOKEN_URL, json={
                'grant_type': DEVICE_GRANT_TYPE,
                'device_code': device_code,
                'client_id': self.client_id,
            }, verify=VERIFY_TLS)
            if resp.status_code == 200:
                self._apply(resp.json())
                self._save_tokens()
                self._fetch_user_id()
                print('Connected to Autodarts!')
                return

            error = resp.json().get('error')
            if error == 'authorization_pending':
                continue
            if error == 'slow_down':
                interval += 5
                continue
            if error == 'expired_token':
                print('The code expired before it was confirmed. Requesting a new one…')
                self._device_login()
                return
            if error == 'access_denied':
                raise RuntimeError('Authorization request was denied')
            raise RuntimeError(f'Device authorization failed: {error}')

        raise RuntimeError('Timed out waiting for authorization')

    def _refresh(self):
        resp = requests.post(REFRESH_URL, json={
            'refresh_token': self._refresh_token,
            'client_id': self.client_id,
        }, verify=VERIFY_TLS)
        resp.raise_for_status()
        self._apply(resp.json())
        self._save_tokens()
        if self.debug:
            print('Token refreshed, expires', self._expires_at)

    def _fetch_user_id(self):
        resp = requests.get(USERINFO_URL, headers={'Authorization': f'Bearer {self.access_token}'}, verify=VERIFY_TLS)
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
                    self._device_login()
                    continue

                now = datetime.now()
                if self._expires_at and (self._expires_at - now).total_seconds() < REFRESH_AHEAD_SECS:
                    if self._refresh_expires_at and now < self._refresh_expires_at:
                        self._refresh()
                    else:
                        print('Refresh token expired — re-authenticating')
                        self._device_login()
            except Exception:
                self.access_token = None
                print('Token refresh failed')

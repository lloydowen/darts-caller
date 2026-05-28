import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# The registered public client ID for darts-caller.
# Override with AUTODARTS_CLIENT_ID in your .env if needed.
AUTODARTS_DEFAULT_CLIENT_ID = 'darts-caller'


def load_client_id() -> str:
    is_one_file_build = hasattr(sys, '_MEIPASS')
    env_path = Path(sys._MEIPASS) / '.env/.env' if is_one_file_build else Path('.env')

    if env_path.exists():
        load_dotenv(dotenv_path=env_path)

    return os.getenv('AUTODARTS_CLIENT_ID', AUTODARTS_DEFAULT_CLIENT_ID)

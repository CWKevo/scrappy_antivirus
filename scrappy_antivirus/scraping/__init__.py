from typing import Optional

import requests

from scrappy_antivirus.constants import ALLOWED_CODES


def grab_text_from_url(url: str) -> Optional[str]:
    try:
        response = requests.get(url)

    except ConnectionError:
        return None

    if response.status_code in ALLOWED_CODES:
        text = response.text

        return text
    
    else:
        return None

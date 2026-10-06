from dataclasses import dataclass
from typing import Dict, Optional

import requests


@dataclass
class RequestResult:
    status_code: int
    text: str
    headers: Dict[str, str]
    elapsed: float
    error: Optional[str] = None


class HttpClient:
    def __init__(self, timeout: float = 8.0, verify_tls: bool = False):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Local-Lab-SQLi-Scanner/1.0"
        })

    def request(self, method: str, url: str, **kwargs) -> RequestResult:
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=False,
                **kwargs,
            )
            return RequestResult(
                status_code=response.status_code,
                text=response.text,
                headers=dict(response.headers),
                elapsed=response.elapsed.total_seconds(),
            )
        except requests.RequestException as exc:
            return RequestResult(
                status_code=0,
                text="",
                headers={},
                elapsed=0,
                error=str(exc),
            )

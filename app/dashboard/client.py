"""HTTP-only Dashboard client; no core, database, scanner or intelligence imports."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen


class DashboardAPIError(RuntimeError):
    pass


class DashboardClient:
    def __init__(self, base_url: str, timeout: float = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get(self, resource: str, **selection) -> dict | list:
        query = urlencode({key: value for key, value in selection.items() if value is not None})
        try:
            with urlopen(f"{self.base_url}/api/{resource}?{query}", timeout=self.timeout) as response:
                return json.load(response)
        except HTTPError as exc:
            try:
                message = json.load(exc)["error"]["message"]
            except (ValueError, KeyError, TypeError):
                message = "API 응답을 확인할 수 없습니다"
            raise DashboardAPIError(f"HTTP {exc.code}: {message}") from exc
        except (URLError, OSError, ValueError) as exc:
            raise DashboardAPIError("API에 연결할 수 없습니다. 주소·서버 실행 상태를 확인하세요.") from exc

"""GitHub App client. Read-only by construction: every installation token is scoped to one repository with
contents:read + metadata:read, and installations whose permissions include anything but `read` are refused."""

import base64
import json
import time
from functools import lru_cache
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.core.config import get_settings

READ_SCOPE = {"contents": "read", "metadata": "read"}
MAX_CONTENT_BYTES = 20 * 1024 * 1024


class GitHubError(Exception):
    pass


class GitHubNotConfigured(GitHubError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: int, private_key_pem: bytes, now: float | None = None) -> str:
    """RS256 JWT for authenticating as the App (10-minute maximum lifetime per GitHub)."""
    now = int(now if now is not None else time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def is_read_only(permissions: dict[str, Any]) -> bool:
    return bool(permissions) and all(v == "read" for v in permissions.values())


class GitHubClient:
    def __init__(self, app_id: int, private_key_pem: bytes, http: httpx.AsyncClient) -> None:
        self._app_id, self._key, self._http = app_id, private_key_pem, http

    def _app_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {app_jwt(self._app_id, self._key)}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    @staticmethod
    def _token_headers(token: str) -> dict[str, str]:
        return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    async def _json(self, r: httpx.Response) -> Any:
        if r.status_code >= 400:
            raise GitHubError(f"GitHub API {r.request.method} {r.request.url.path} -> {r.status_code}")
        return r.json()

    async def installation(self, installation_id: int) -> dict:
        return await self._json(await self._http.get(f"/app/installations/{installation_id}", headers=self._app_headers()))

    async def _token(self, installation_id: int, repository_ids: list[int] | None) -> str:
        body: dict[str, Any] = {"permissions": READ_SCOPE}
        if repository_ids is not None:
            body["repository_ids"] = repository_ids
        data = await self._json(await self._http.post(
            f"/app/installations/{installation_id}/access_tokens", headers=self._app_headers(), json=body))
        return data["token"]

    async def installation_repos(self, installation_id: int) -> list[dict]:
        token = await self._token(installation_id, None)
        repos, page = [], 1
        while True:
            data = await self._json(await self._http.get(
                "/installation/repositories", params={"per_page": 100, "page": page}, headers=self._token_headers(token)))
            repos += data.get("repositories", [])
            if len(data.get("repositories", [])) < 100:
                return repos
            page += 1

    async def repo_session(self, installation_id: int, repo_id: int) -> "RepoSession":
        return RepoSession(self._http, self._token_headers(await self._token(installation_id, [repo_id])), repo_id)


class RepoSession:
    """Read calls for one repository with a token that can see nothing else."""

    def __init__(self, http: httpx.AsyncClient, headers: dict[str, str], repo_id: int) -> None:
        self._http, self._headers, self._base = http, headers, f"/repositories/{repo_id}"

    async def _get(self, path: str, **params) -> Any:
        r = await self._http.get(self._base + path, headers=self._headers, params=params or None)
        if r.status_code >= 400:
            raise GitHubError(f"GitHub API GET {path} -> {r.status_code}")
        return r.json()

    async def metadata(self) -> dict:
        return await self._get("")

    async def tree(self, ref: str) -> tuple[str, list[str], bool]:
        data = await self._get(f"/git/trees/{ref}", recursive="1")
        paths = [e["path"] for e in data.get("tree", []) if e.get("type") == "blob"]
        return data["sha"], paths, bool(data.get("truncated"))

    async def file(self, path: str, ref: str) -> bytes | None:
        data = await self._get(f"/contents/{path}", ref=ref)
        if not isinstance(data, dict) or data.get("type") != "file" or data.get("size", 0) > MAX_CONTENT_BYTES:
            return None
        if data.get("encoding") == "base64":
            return base64.b64decode(data.get("content", ""))
        return None  # large files come back without inline content; treated as not read


@lru_cache
def _private_key() -> bytes:
    s = get_settings()
    if not (s.github_app_id and s.github_private_key_file):
        raise GitHubNotConfigured("GitHub App is not configured")
    return s.github_private_key_file.read_bytes()


def webhook_secret() -> bytes:
    s = get_settings()
    if not s.github_webhook_secret_file:
        raise GitHubNotConfigured("GitHub webhook secret is not configured")
    return s.github_webhook_secret_file.read_bytes().strip()


_client_override: GitHubClient | None = None


def get_github() -> GitHubClient:
    """Process-wide client; tests set `_client_override`."""
    if _client_override is not None:
        return _client_override
    s = get_settings()
    http = httpx.AsyncClient(base_url=s.github_api_url, timeout=30, follow_redirects=False)
    return GitHubClient(s.github_app_id, _private_key(), http)

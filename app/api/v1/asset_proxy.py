"""
Asset proxy API route.

Streams assets from assets.grok.com in real-time, using HMAC-signed URLs
to prevent unauthorized access. Uses curl_cffi with browser TLS fingerprint
impersonation to bypass Cloudflare detection.
"""

import hashlib
import hmac
import time

from curl_cffi.requests import AsyncSession
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.core.config import get_config
from app.core.logger import logger
from app.services.reverse.utils.headers import build_headers
from app.services.token import get_token_manager

router = APIRouter(tags=["AssetProxy"])

# Signature validity window (seconds)
_SIG_TTL = 3600

ASSETS_BASE = "https://assets.grok.com"


def _get_signing_key() -> str:
    """Get the HMAC signing key from config, falling back to api_key."""
    key = get_config("app.app_key") or get_config("app.api_key") or "grok2api-default"
    return key


def sign_asset_url(path: str, media_type: str = "video") -> str:
    """Generate a signed proxy URL path.

    Returns the query string portion: sig=...&ts=...
    """
    ts = str(int(time.time()))
    key = _get_signing_key()
    payload = f"{media_type}:{path}:{ts}"
    sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"sig={sig}&ts={ts}"


def verify_signature(path: str, media_type: str, sig: str, ts: str) -> bool:
    """Verify the HMAC signature."""
    try:
        timestamp = int(ts)
    except (ValueError, TypeError):
        return False
    if abs(time.time() - timestamp) > _SIG_TTL:
        return False
    key = _get_signing_key()
    payload = f"{media_type}:{path}:{ts}"
    expected = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(sig, expected)


async def _get_any_token() -> str:
    """Get any available token from the pool for asset download."""
    token_mgr = await get_token_manager()
    await token_mgr.reload_if_stale()
    for pool_name in list(token_mgr.pools.keys()):
        token = token_mgr.get_token(pool_name)
        if token:
            return token
    raise HTTPException(status_code=503, detail="No available tokens for asset proxy")


@router.get("/{media_type}/{path:path}")
async def proxy_asset(
    media_type: str,
    path: str,
    sig: str = Query(...),
    ts: str = Query(...),
):
    """
    Real-time asset proxy. Streams content from assets.grok.com
    using curl_cffi with browser TLS impersonation + SSO cookie.
    """
    if media_type not in ("video", "image"):
        raise HTTPException(status_code=400, detail="Invalid media type")

    if not verify_signature(path, media_type, sig, ts):
        raise HTTPException(status_code=403, detail="Invalid or expired signature")

    asset_path = f"/{path}" if not path.startswith("/") else path
    token = await _get_any_token()
    url = f"{ASSETS_BASE}{asset_path}"

    # Build headers using the same builder as other reverse endpoints
    headers = build_headers(
        cookie_token=token,
        content_type=None,
        origin="https://assets.grok.com",
        referer="https://grok.com/",
    )
    headers["Cache-Control"] = "no-cache"
    headers["Pragma"] = "no-cache"
    headers["Sec-Fetch-Mode"] = "navigate"
    headers["Sec-Fetch-User"] = "?1"
    headers["Upgrade-Insecure-Requests"] = "1"

    # Proxy config
    base_proxy = get_config("proxy.base_proxy_url")
    asset_proxy = get_config("proxy.asset_proxy_url")
    proxy = asset_proxy or base_proxy
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Browser impersonation
    browser = get_config("proxy.browser")
    timeout = get_config("asset.download_timeout") or 120

    session = AsyncSession()
    try:
        resp = await session.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            allow_redirects=True,
            impersonate=browser,
            stream=True,
        )
    except Exception as e:
        await session.close()
        logger.error(f"Asset proxy curl_cffi request failed: {e}")
        raise HTTPException(status_code=502, detail=f"Upstream connection failed: {e}")

    if resp.status_code != 200:
        await session.close()
        logger.error(f"Asset proxy upstream returned {resp.status_code}")
        raise HTTPException(
            status_code=resp.status_code,
            detail=f"Upstream returned {resp.status_code}",
        )

    content_type = resp.headers.get("content-type", "application/octet-stream")

    async def stream_response():
        try:
            if hasattr(resp, "aiter_content"):
                async for chunk in resp.aiter_content():
                    if chunk:
                        yield chunk
            else:
                yield resp.content
        finally:
            await session.close()

    return StreamingResponse(
        stream_response(),
        media_type=content_type,
        headers={
            "Cache-Control": "public, max-age=86400",
            "Access-Control-Allow-Origin": "*",
        },
    )


__all__ = ["router", "sign_asset_url"]

"""
Asset proxy API route.

Streams assets from assets.grok.com in real-time, using HMAC-signed URLs
to prevent unauthorized access. Uses aiohttp (pure Python) instead of
curl_cffi to ensure compatibility with serverless platforms like Vercel.
"""

import hashlib
import hmac
import time

import aiohttp
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.core.config import get_config
from app.core.logger import logger
from app.services.reverse.utils.headers import build_sso_cookie
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


def _build_asset_headers(token: str) -> dict:
    """Build minimal headers for assets.grok.com download."""
    user_agent = get_config("proxy.user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    return {
        "Cookie": build_sso_cookie(token),
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": "https://grok.com/",
        "Origin": "https://grok.com",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }


@router.get("/{media_type}/{path:path}")
async def proxy_asset(
    media_type: str,
    path: str,
    sig: str = Query(...),
    ts: str = Query(...),
):
    """
    Real-time asset proxy. Streams content from assets.grok.com
    using aiohttp with SSO cookie auth. URL must be HMAC-signed.
    """
    if media_type not in ("video", "image"):
        raise HTTPException(status_code=400, detail="Invalid media type")

    if not verify_signature(path, media_type, sig, ts):
        raise HTTPException(status_code=403, detail="Invalid or expired signature")

    asset_path = f"/{path}" if not path.startswith("/") else path
    token = await _get_any_token()
    url = f"{ASSETS_BASE}{asset_path}"
    headers = _build_asset_headers(token)

    # Determine proxy for outbound request
    proxy_url = get_config("proxy.asset_proxy_url") or get_config("proxy.base_proxy_url")

    timeout = aiohttp.ClientTimeout(total=120)
    session = aiohttp.ClientSession(timeout=timeout)

    try:
        resp = await session.get(url, headers=headers, proxy=proxy_url or None)
    except Exception as e:
        await session.close()
        logger.error(f"Asset proxy aiohttp request failed: {e}")
        raise HTTPException(status_code=502, detail=f"Upstream connection failed: {e}")

    if resp.status != 200:
        body = await resp.text()
        await resp.release()
        await session.close()
        logger.error(f"Asset proxy upstream returned {resp.status}: {body[:200]}")
        raise HTTPException(
            status_code=resp.status,
            detail=f"Upstream returned {resp.status}",
        )

    content_type = resp.headers.get("content-type", "application/octet-stream")

    async def stream_response():
        try:
            async for chunk in resp.content.iter_chunked(64 * 1024):
                if chunk:
                    yield chunk
        finally:
            await resp.release()
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

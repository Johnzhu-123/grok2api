"""
Asset proxy API route.

Streams assets from assets.grok.com in real-time, using HMAC-signed URLs
to prevent unauthorized access. This avoids the need for local file caching
and works on serverless platforms like Vercel.
"""

import hashlib
import hmac
import time

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.core.config import get_config
from app.core.logger import logger
from app.services.reverse.assets_download import AssetsDownloadReverse
from app.services.reverse.utils.session import ResettableSession
from app.services.token import get_token_manager

router = APIRouter(tags=["AssetProxy"])

# Signature validity window (seconds)
_SIG_TTL = 3600


def _get_signing_key() -> str:
    """Get the HMAC signing key from config, falling back to api_key."""
    key = get_config("app.app_key") or get_config("app.api_key") or "grok2api-default"
    return key


def sign_asset_url(path: str, media_type: str = "video") -> str:
    """Generate a signed proxy URL path.

    Returns the query string portion: ?sig=...&ts=...
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
    # Try all known pools
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
    using a token from the pool. URL must be HMAC-signed.
    """
    if media_type not in ("video", "image"):
        raise HTTPException(status_code=400, detail="Invalid media type")

    # Verify signature
    if not verify_signature(path, media_type, sig, ts):
        raise HTTPException(status_code=403, detail="Invalid or expired signature")

    # Normalize path
    asset_path = f"/{path}" if not path.startswith("/") else path

    # Get a token
    token = await _get_any_token()

    # Stream from assets.grok.com
    browser = get_config("proxy.browser")
    session = ResettableSession(impersonate=browser) if browser else ResettableSession()

    try:
        response = await AssetsDownloadReverse.request(session, token, asset_path)
    except Exception as e:
        await session.close()
        logger.error(f"Asset proxy download failed: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch asset")

    content_type = response.headers.get("content-type", "application/octet-stream")

    async def stream_response():
        try:
            if hasattr(response, "aiter_content"):
                async for chunk in response.aiter_content():
                    if chunk:
                        yield chunk
            else:
                yield response.content
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

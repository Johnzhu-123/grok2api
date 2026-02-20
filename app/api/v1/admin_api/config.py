import os

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import verify_app_key
from app.core.config import config
from app.core.storage import (
    get_storage as _get_storage,
    LocalStorage,
    RedisStorage,
    SQLStorage,
)

router = APIRouter()


@router.get("/health")
async def health_check():
    """数据库连接诊断（无需认证，部署后可删除）"""
    storage = _get_storage()
    result = {
        "storage_type": os.getenv("SERVER_STORAGE_TYPE", "local"),
        "storage_class": storage.__class__.__name__,
        "config_loaded": bool(config._config),
        "app_key_source": "unknown",
    }

    # 检查配置是否从数据库加载
    app_key = config.get("app.app_key")
    if app_key and app_key != "grok2api":
        result["app_key_source"] = "database (custom password found)"
    elif app_key == "grok2api":
        result["app_key_source"] = "default (may be from DB or fallback)"
    else:
        result["app_key_source"] = "missing"

    # 测试数据库连接
    if isinstance(storage, SQLStorage):
        try:
            data = await storage.load_config()
            if data is None:
                result["db_connection"] = "FAILED (returned None)"
            else:
                result["db_connection"] = "OK"
                result["db_config_count"] = len(
                    [k for section in data.values() if isinstance(section, dict) for k in section]
                )
        except Exception as e:
            result["db_connection"] = f"ERROR: {e}"
    else:
        result["db_connection"] = "N/A (not SQL storage)"

    return result


@router.get("/verify", dependencies=[Depends(verify_app_key)])
async def admin_verify():
    """验证后台访问密钥（app_key）"""
    return {"status": "success"}


@router.get("/config", dependencies=[Depends(verify_app_key)])
async def get_config():
    """获取当前配置"""
    # 暴露原始配置字典
    return config._config


@router.post("/config", dependencies=[Depends(verify_app_key)])
async def update_config(data: dict):
    """更新配置"""
    try:
        await config.update(data)
        return {"status": "success", "message": "配置已更新"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/storage", dependencies=[Depends(verify_app_key)])
async def get_storage_type():
    """获取当前存储模式"""
    storage_type = os.getenv("SERVER_STORAGE_TYPE", "").lower()
    if not storage_type:
        storage = _get_storage()
        if isinstance(storage, LocalStorage):
            storage_type = "local"
        elif isinstance(storage, RedisStorage):
            storage_type = "redis"
        elif isinstance(storage, SQLStorage):
            storage_type = {
                "mysql": "mysql",
                "mariadb": "mysql",
                "postgres": "pgsql",
                "postgresql": "pgsql",
                "pgsql": "pgsql",
            }.get(storage.dialect, storage.dialect)
    return {"type": storage_type or "local"}

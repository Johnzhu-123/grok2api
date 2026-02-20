"""快速测试数据库连接和配置状态"""
import asyncio
import ssl


async def main():
    try:
        import asyncpg
    except ImportError:
        print("asyncpg 未安装，尝试安装...")
        import subprocess
        subprocess.check_call(["pip", "install", "asyncpg"])
        import asyncpg

    url = "postgresql://neondb_owner:npg_t5vYKbFXWgq8@ep-snowy-flower-a1a48izn-pooler.ap-southeast-1.aws.neon.tech/neondb"

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    print("1. 尝试连接数据库...")
    try:
        conn = await asyncpg.connect(url, ssl=ssl_ctx)
        print("   连接成功!")
    except Exception as e:
        print(f"   连接失败: {e}")
        return

    print("\n2. 检查 app_config 表...")
    try:
        rows = await conn.fetch("SELECT section, key_name, value FROM app_config ORDER BY section, key_name")
        if not rows:
            print("   app_config 表为空（无数据）")
        else:
            print(f"   找到 {len(rows)} 条配置:")
            for r in rows:
                val_display = r["value"]
                if len(val_display) > 80:
                    val_display = val_display[:80] + "..."
                print(f"   [{r['section']}] {r['key_name']} = {val_display}")
    except Exception as e:
        print(f"   查询失败 (表可能不存在): {e}")

    print("\n3. 检查 app_key (后台密码)...")
    try:
        row = await conn.fetchrow(
            "SELECT value FROM app_config WHERE section='app' AND key_name='app_key'"
        )
        if row:
            print(f"   当前密码: {row['value']}")
        else:
            print("   未找到 app_key 配置（将使用默认值 grok2api）")
    except Exception as e:
        print(f"   查询失败: {e}")

    print("\n4. 检查 tokens 表...")
    try:
        count = await conn.fetchval("SELECT COUNT(*) FROM tokens")
        print(f"   Token 总数: {count}")
    except Exception as e:
        print(f"   查询失败 (表可能不存在): {e}")

    await conn.close()
    print("\n完成!")


asyncio.run(main())

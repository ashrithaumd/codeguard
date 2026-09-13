import psycopg

from codeguard.config import get_settings


async def check_db_connection() -> bool:
    """Best-effort SELECT 1 against Postgres. Returns False on any
    failure rather than raising — /ready reports unhealthy, it doesn't
    500.
    """
    settings = get_settings()
    try:
        async with await psycopg.AsyncConnection.connect(
            settings.database_url, connect_timeout=3
        ) as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1")
                await cur.fetchone()
        return True
    except Exception:
        return False

# Central configuration. All credentials come from environment variables /
# backend/.env — never hardcode secrets. Each provider reports whether it is
# configured so the app can degrade gracefully (spec sections 6, 24, 25).
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # AI
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash-lite"

    # URL reputation
    virustotal_api_key: str = ""

    # Graph intelligence
    neo4j_uri: str = ""           # e.g. neo4j+s://xxxxxxxx.databases.neo4j.io
    neo4j_username: str = "neo4j"
    neo4j_password: str = ""

    # Structured storage + analyst auth
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_role_key: str = ""

    # App
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    rate_limit_per_minute: int = 30
    max_body_bytes: int = 8 * 1024 * 1024  # 8 MB (screenshots can be large)

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @property
    def cors_origin_list(self) -> list:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def gemini_configured(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def neo4j_configured(self) -> bool:
        return bool(self.neo4j_uri and self.neo4j_password)

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_anon_key)

    @property
    def supabase_admin_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_role_key)


settings = Settings()

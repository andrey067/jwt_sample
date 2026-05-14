"""Configurações do projeto JWT Sample."""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Configurações da aplicação."""

    # JWT Settings
    secret_key: str = "sua_chave_secreta_muito_segura_aqui_2024"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # App Settings
    app_name: str = "JWT Sample API"

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    """Retorna as configurações cacheadas."""
    return Settings()
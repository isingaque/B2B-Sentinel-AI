from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://dutyai:local_development_only@localhost:5432/dutyai"
    redis_url: str = "redis://localhost:6379/0"
    prometheus_url: str = "http://localhost:9090"
    demo_exporter_url: str = "http://localhost:9102"
    demo_token: str = "change_me_shared_demo_secret"
    jwt_secret: str = "replace_with_at_least_32_random_characters_before_public_deploy"
    demo_password: str = "DemoPass123!"
    embedding_backend: str = "hash"

settings = Settings()

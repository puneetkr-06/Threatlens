from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Application configuration loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # WAF Server & Upstream Reverse Proxy
    waf_host: str = Field(default="0.0.0.0", alias="WAF_HOST")
    waf_port: int = Field(default=8000, alias="WAF_PORT")
    upstream_url: str = Field(default="http://localhost:9000", alias="UPSTREAM_URL")

    # Redis Cache
    redis_host: str = Field(default="localhost", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_db: int = Field(default=0, alias="REDIS_DB")
    redis_password: str | None = Field(default=None, alias="REDIS_PASSWORD")
    cache_ttl_seconds: int = Field(default=3600, alias="CACHE_TTL_SECONDS")

    # Pinecone Vector DB
    pinecone_api_key: str = Field(default="", alias="PINECONE_API_KEY")
    pinecone_index_name: str = Field(default="semantic-waf-vectors", alias="PINECONE_INDEX_NAME")
    pinecone_cloud: str = Field(default="aws", alias="PINECONE_CLOUD")
    pinecone_region: str = Field(default="us-east-1", alias="PINECONE_REGION")

    # Google Gemini Embeddings & LLM
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    google_api_key: str = Field(default="", alias="GOOGLE_API_KEY")
    embedding_model_name: str = Field(default="models/gemini-embedding-001", alias="EMBEDDING_MODEL_NAME")
    embedding_dimension: int = Field(default=768, alias="EMBEDDING_DIMENSION")
    llm_model_name: str = Field(default="gemini-3.8-flash", alias="LLM_MODEL_NAME")

    # Semantic Detection Thresholds
    waf_high_threshold: float = Field(default=0.75, alias="WAF_HIGH_THRESHOLD")
    waf_low_threshold: float = Field(default=0.65, alias="WAF_LOW_THRESHOLD")

    @property
    def effective_gemini_key(self) -> str:
        """Returns GEMINI_API_KEY or GOOGLE_API_KEY if either is configured."""
        return self.gemini_api_key or self.google_api_key


# Global singleton instance for settings
settings = Settings()

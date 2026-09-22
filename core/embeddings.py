import logging
from typing import List
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from config import settings

logger = logging.getLogger("WAF.Embeddings")


class EmbeddingService:
    """
    Asynchronous vector embedding generator powered by Google Gemini (text-embedding-004).
    Converts canonical HTTP payload strings into high-dimensional vector embeddings.
    """

    def __init__(self):
        self._client: GoogleGenerativeAIEmbeddings | None = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Instantiate LangChain Google Gemini Embeddings client."""
        api_key = settings.effective_gemini_key
        if api_key:
            try:
                self._client = GoogleGenerativeAIEmbeddings(
                    model=settings.embedding_model_name,
                    google_api_key=api_key,
                    output_dimensionality=settings.embedding_dimension,
                )
                logger.info(f"Initialized Google Gemini Embeddings with model: {settings.embedding_model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize Google Gemini Embeddings: {e}")
                self._client = None
        else:
            logger.warning(
                "GEMINI_API_KEY (or GOOGLE_API_KEY) is not set. Embedding service will fail if invoked without fallback."
            )

    async def get_embedding(self, text: str) -> List[float]:
        """
        Asynchronously generate embedding vector for a single payload string.
        """
        if not self._client:
            raise ValueError("Embedding client is not configured. Please provide GEMINI_API_KEY.")

        # Truncate text if it exceeds token length limits (safe bound for payloads)
        truncated_text = text[:8000]
        return await self._client.aembed_query(truncated_text)

    async def get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """
        Batch generation of embeddings for vector DB seeding.
        """
        if not self._client:
            raise ValueError("Embedding client is not configured. Please provide GEMINI_API_KEY.")

        truncated_texts = [t[:8000] for t in texts]
        return await self._client.aembed_documents(truncated_texts)


# Singleton instance
embedding_service = EmbeddingService()

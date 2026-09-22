import asyncio
import logging
from typing import Tuple, Dict, Any, Optional
from pinecone import Pinecone
from config import settings

logger = logging.getLogger("WAF.Pinecone")


class PineconeWAFClient:
    """
    Manages semantic similarity queries against a Pinecone vector index
    populated with known malicious payload signatures and zero-day patterns.
    """

    def __init__(self):
        self._pc: Optional[Pinecone] = None
        self._index = None
        self._initialize()

    def _initialize(self) -> None:
        """Initialize Pinecone client and connect to the target index."""
        if not settings.pinecone_api_key:
            logger.warning("PINECONE_API_KEY is not configured.")
            return

        try:
            self._pc = Pinecone(api_key=settings.pinecone_api_key)
            self._index = self._pc.Index(settings.pinecone_index_name)
            logger.info(f"Connected to Pinecone index: '{settings.pinecone_index_name}'")
        except Exception as e:
            logger.error(f"Failed to initialize Pinecone client: {e}")
            self._index = None

    async def query_similarity(
        self,
        vector: list[float],
        top_k: int = 3
    ) -> Tuple[float, Optional[Dict[str, Any]]]:
        """
        Executes an asynchronous vector similarity query.
        Returns:
            Tuple[highest_cosine_similarity_score, metadata_of_top_match]
        """
        if not self._index:
            logger.warning("Pinecone index unavailable. Defaulting similarity score to 0.0.")
            return 0.0, None

        # Pinecone SDK call is synchronous; run in background thread pool to avoid blocking event loop
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(
                None,
                lambda: self._index.query(
                    vector=vector,
                    top_k=top_k,
                    include_metadata=True
                )
            )

            matches = response.get("matches", [])
            if not matches:
                return 0.0, None

            # Get the match with the highest cosine similarity
            top_match = matches[0]
            max_score = float(top_match.get("score", 0.0))
            metadata = top_match.get("metadata", {})

            return max_score, metadata

        except Exception as e:
            logger.error(f"Pinecone similarity search failed: {e}")
            return 0.0, None


# Singleton instance
pinecone_client = PineconeWAFClient()

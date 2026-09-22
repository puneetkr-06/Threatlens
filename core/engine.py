import logging
import time
from typing import Dict, Any, Tuple
from fastapi import Request
from config import settings
from core.inspector import RequestInspector
from core.cache import waf_cache
from core.embeddings import embedding_service
from core.pinecone_client import pinecone_client
from core.llm_fallback import llm_fallback_analyzer

logger = logging.getLogger("WAF.Engine")


class WAFDecisionEngine:
    """
    Central orchestration engine for the Semantic WAF:
    1. Extracts & canonicalizes request payload.
    2. Queries Redis cache for sub-5ms verdicts.
    3. Generates high-dimensional vector embeddings.
    4. Performs Pinecone cosine similarity search against malicious signatures.
    5. Applies thresholding & routes boundary cases to LangChain LLM analysis.
    """

    async def evaluate_request(self, request: Request) -> Tuple[Dict[str, Any], bytes]:
        """
        Executes the full WAF evaluation pipeline for an incoming HTTP request.

        Returns:
            Tuple[decision_dict, raw_body_bytes]
            decision_dict contains:
              - verdict: 'ALLOW' | 'BLOCK'
              - score: float
              - reason: str
              - source: 'cache' | 'vector_db' | 'llm_fallback'
              - latency_ms: float
        """
        start_time = time.perf_counter()

        # Step 1: Request Inspection & Canonicalization
        canonical_payload, payload_hash, raw_body = await RequestInspector.extract_and_canonicalize(request)

        # Step 2: Redis Fast Caching (Sub-5ms evaluation for known payloads)
        cached_verdict = await waf_cache.get_verdict(payload_hash)
        if cached_verdict:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            cached_verdict["latency_ms"] = round(latency_ms, 2)
            logger.info(f"[CACHE HIT] Verdict: {cached_verdict['verdict']} in {latency_ms:.2f}ms")
            return cached_verdict, raw_body

        # Step 3: Vector Embedding Generation
        try:
            vector = await embedding_service.get_embedding(canonical_payload)
        except Exception as e:
            logger.error(f"Embedding generation error: {e}. Defaulting to fail-open/upstream inspection.")
            vector = None

        if not vector:
            # Fallback if embeddings are unavailable
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                "verdict": "ALLOW",
                "score": 0.0,
                "reason": "Embedding engine bypassed/unavailable",
                "source": "fallback",
                "latency_ms": round(latency_ms, 2)
            }, raw_body

        # Step 4: Semantic Search in Pinecone
        similarity_score, top_match = await pinecone_client.query_similarity(vector, top_k=3)

        decision: Dict[str, Any] = {}

        # Step 5: Verdict Logic
        if similarity_score >= settings.waf_high_threshold:
            # High similarity: definite attack vector -> BLOCK
            attack_type = top_match.get("attack_type", "Known_Malicious_Pattern") if top_match else "Exploit"
            reason = f"High semantic similarity ({similarity_score:.3f}) to {attack_type}"
            decision = {
                "verdict": "BLOCK",
                "score": round(similarity_score, 4),
                "reason": reason,
                "source": "vector_db"
            }
            await waf_cache.set_verdict(payload_hash, "BLOCK", similarity_score, reason)

        elif similarity_score <= settings.waf_low_threshold:
            # Low similarity: benign payload -> ALLOW
            reason = f"Low semantic similarity ({similarity_score:.3f}) below threshold"
            decision = {
                "verdict": "ALLOW",
                "score": round(similarity_score, 4),
                "reason": reason,
                "source": "vector_db"
            }
            await waf_cache.set_verdict(payload_hash, "ALLOW", similarity_score, reason)

        else:
            # Boundary range (LOW_THRESHOLD < score < HIGH_THRESHOLD) -> LLM Fallback Analysis
            logger.info(
                f"[BOUNDARY CASE] Similarity {similarity_score:.3f} between [{settings.waf_low_threshold}, "
                f"{settings.waf_high_threshold}]. Invoking LLM fallback..."
            )
            llm_result = await llm_fallback_analyzer.analyze(canonical_payload, similarity_score)
            
            reason = f"LLM Verdict [{llm_result.attack_type or 'General'}]: {llm_result.reasoning}"
            decision = {
                "verdict": llm_result.verdict,
                "score": round(similarity_score, 4),
                "reason": reason,
                "source": "llm_fallback"
            }
            await waf_cache.set_verdict(payload_hash, llm_result.verdict, similarity_score, reason)

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        decision["latency_ms"] = round(latency_ms, 2)
        return decision, raw_body


# Singleton instance
waf_engine = WAFDecisionEngine()

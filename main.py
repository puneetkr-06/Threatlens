import logging
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from config import settings
from core.cache import waf_cache
from core.engine import waf_engine
from middleware.waf_middleware import proxy_handler

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
)
logger = logging.getLogger("WAF.Main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle hook for managing persistent connection pools."""
    logger.info("Initializing Semantic WAF services...")
    await waf_cache.connect()
    await proxy_handler.start()
    yield
    logger.info("Shutting down Semantic WAF services...")
    await waf_cache.disconnect()
    await proxy_handler.stop()


app = FastAPI(
    title="LLM-Powered Semantic Web Application Firewall (WAF)",
    description="Zero-day attack & malicious intent detector using vector embeddings and LangChain fallback analysis.",
    version="1.0.0",
    lifespan=lifespan
)


class InspectPayloadRequest(BaseModel):
    payload: str
    method: str = "GET"
    path: str = "/api/test"


@app.get("/waf/health", tags=["Monitoring"])
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for Kubernetes liveness/readiness probes."""
    return {
        "status": "healthy",
        "redis_connected": waf_cache._redis is not None,
        "high_threshold": settings.waf_high_threshold,
        "low_threshold": settings.waf_low_threshold,
        "embedding_model": settings.embedding_model_name,
        "upstream_target": settings.upstream_url,
    }


@app.post("/waf/inspect", tags=["DevSecOps Inspection"])
async def inspect_raw_payload(body: InspectPayloadRequest) -> Dict[str, Any]:
    """
    Direct inspection endpoint for DevSecOps, SOC analysts, and automated integration tests.
    Evaluates arbitrary payloads without triggering upstream proxying.
    """
    from core.inspector import RequestInspector
    from core.embeddings import embedding_service
    from core.pinecone_client import pinecone_client
    from core.llm_fallback import llm_fallback_analyzer

    norm_payload = RequestInspector.normalize_string(body.payload)
    vector = await embedding_service.get_embedding(norm_payload)
    score, top_match = await pinecone_client.query_similarity(vector, top_k=3)

    if score >= settings.waf_high_threshold:
        verdict = "BLOCK"
        source = "vector_db"
        reason = f"High similarity ({score:.3f}) to {top_match.get('attack_type', 'Malicious')}"
    elif score <= settings.waf_low_threshold:
        verdict = "ALLOW"
        source = "vector_db"
        reason = f"Low similarity ({score:.3f}) below threshold"
    else:
        llm_res = await llm_fallback_analyzer.analyze(norm_payload, score)
        verdict = llm_res.verdict
        source = "llm_fallback"
        reason = f"LLM Verdict [{llm_res.attack_type or 'General'}]: {llm_res.reasoning}"

    return {
        "input_payload": body.payload,
        "normalized_payload": norm_payload,
        "similarity_score": round(score, 4),
        "verdict": verdict,
        "source": source,
        "reason": reason,
        "matched_signature": top_match
    }


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    include_in_schema=False
)
async def reverse_proxy_waf_interceptor(path: str, request: Request) -> Response:
    """
    Primary reverse proxy interceptor.
    Intercepts all incoming HTTP traffic, executes the 5-step semantic WAF pipeline,
    and either blocks the request (HTTP 403) or proxies to the protected upstream backend.
    """
    decision, raw_body = await waf_engine.evaluate_request(request)

    if decision["verdict"] == "BLOCK":
        logger.warning(
            f"[THREAT BLOCKED] {request.method} {request.url.path} | "
            f"Score: {decision['score']} | Reason: {decision['reason']} | Latency: {decision['latency_ms']}ms"
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden - Malicious Request Detected by Semantic WAF",
                "verdict": "BLOCK",
                "threat_score": decision["score"],
                "reason": decision["reason"],
                "evaluation_source": decision["source"],
                "latency_ms": decision["latency_ms"]
            },
            headers={
                "X-WAF-Action": "BLOCK",
                "X-WAF-Latency": f"{decision['latency_ms']}ms"
            }
        )

    # Benign request: dispatch to upstream protected server
    logger.info(
        f"[TRAFFIC ALLOWED] {request.method} {request.url.path} | "
        f"Score: {decision['score']} | Source: {decision['source']} | Latency: {decision['latency_ms']}ms"
    )
    upstream_response = await proxy_handler.forward(request, raw_body)
    upstream_response.headers["X-WAF-Verdict"] = "ALLOW"
    upstream_response.headers["X-WAF-Latency"] = f"{decision['latency_ms']}ms"
    return upstream_response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.waf_host, port=settings.waf_port, reload=True)

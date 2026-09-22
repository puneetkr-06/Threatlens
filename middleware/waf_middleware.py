import logging
from typing import Dict, Any
import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from config import settings
from core.engine import waf_engine

logger = logging.getLogger("WAF.Middleware")


class ReverseProxyHandler:
    """
    Asynchronous reverse proxy dispatcher.
    Forwards allowed requests to the upstream application service.
    """

    def __init__(self):
        # Persistent async client with connection pooling for high throughput
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        """Initialize HTTPX connection pool."""
        self._client = httpx.AsyncClient(
            base_url=settings.upstream_url,
            timeout=httpx.Timeout(10.0, connect=3.0),
            limits=httpx.Limits(max_keepalive_connections=100, max_connections=200),
            follow_redirects=False,
        )
        logger.info(f"Initialized Reverse Proxy routing to upstream: {settings.upstream_url}")

    async def stop(self) -> None:
        """Close connection pool."""
        if self._client:
            await self._client.aclose()
            logger.info("Closed Reverse Proxy upstream client.")

    async def forward(self, request: Request, raw_body: bytes) -> Response:
        """
        Forward the validated request upstream and return upstream response.
        """
        if not self._client:
            return JSONResponse(
                status_code=502,
                content={"error": "Bad Gateway", "details": "Upstream client not initialized"}
            )

        # Reconstruct path and query
        url_path = request.url.path
        if request.url.query:
            url_path = f"{url_path}?{request.url.query}"

        # Strip host header to prevent host-header poisoning upstream
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        try:
            upstream_res = await self._client.request(
                method=request.method,
                url=url_path,
                headers=headers,
                content=raw_body,
            )

            # Exclude hop-by-hop headers
            excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
            filtered_headers = {
                k: v for k, v in upstream_res.headers.items() if k.lower() not in excluded_headers
            }

            return Response(
                content=upstream_res.content,
                status_code=upstream_res.status_code,
                headers=filtered_headers,
                media_type=upstream_res.headers.get("content-type"),
            )
        except httpx.ConnectError:
            logger.error(f"Failed to connect to upstream server at {settings.upstream_url}")
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Upstream Unavailable",
                    "details": f"Could not connect to protected backend server at {settings.upstream_url}"
                }
            )
        except Exception as e:
            logger.error(f"Error forwarding request to upstream: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": "Internal Proxy Error", "details": str(e)}
            )


# Singleton proxy dispatcher
proxy_handler = ReverseProxyHandler()


class SemanticWAFMiddleware(BaseHTTPMiddleware):
    """
    Starlette HTTP Middleware for applications that want to embed the Semantic WAF
    directly in their FastAPI application pipeline instead of standalone proxy mode.
    """

    async def dispatch(self, request: Request, call_next):
        # Bypass WAF evaluation for internal health checks
        if request.url.path in {"/health", "/waf/status"}:
            return await call_next(request)

        decision, _ = await waf_engine.evaluate_request(request)

        if decision["verdict"] == "BLOCK":
            logger.warning(
                f"[WAF BLOCKED] Path: {request.url.path} | Reason: {decision['reason']} | "
                f"Score: {decision['score']} | Source: {decision['source']}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access Denied by Semantic WAF",
                    "verdict": "BLOCK",
                    "reason": decision["reason"],
                    "threat_score": decision["score"],
                    "evaluation_source": decision["source"],
                    "latency_ms": decision["latency_ms"],
                }
            )

        # Request is benign - pass to downstream application
        response = await call_next(request)
        response.headers["X-WAF-Verdict"] = "ALLOW"
        response.headers["X-WAF-Latency"] = f"{decision['latency_ms']}ms"
        return response

import hashlib
import urllib.parse
from typing import Tuple
from fastapi import Request


class RequestInspector:
    """
    Extracts, normalizes, and canonicalizes incoming HTTP request elements
    (URL path, query strings, sensitive headers, and payload body) for
    vector embedding generation and cryptographic hashing.
    """

    # Headers commonly targeted for injection, header tampering, or evasion
    MONITORED_HEADERS = {
        "user-agent",
        "referer",
        "origin",
        "authorization",
        "x-forwarded-for",
        "x-custom-header",
        "cookie",
    }

    @staticmethod
    def normalize_string(raw_val: str) -> str:
        """
        Recursively URL-decodes and normalizes strings to counter multi-layer
        evasion tactics (e.g., %2527 -> %27 -> ').
        """
        current = raw_val
        for _ in range(3):  # Unpack up to 3 layers of URL-encoding
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
        return current.strip()

    @classmethod
    async def extract_and_canonicalize(cls, req: Request) -> Tuple[str, str, bytes]:
        """
        Extracts all inspectable parts of the request, builds a canonical
        representation for embedding and cache key hashing, and preserves
        the raw body for upstream forwarding.

        Returns:
            Tuple[canonical_payload, payload_hash, raw_body_bytes]
        """
        # Read the raw body and preserve it for downstream proxying
        raw_body = await req.body()
        body_text = ""
        if raw_body:
            try:
                body_text = raw_body.decode("utf-8", errors="replace")
            except Exception:
                body_text = str(raw_body)

        normalized_body = cls.normalize_string(body_text)

        # Extract and normalize query params
        query_items = []
        for k, v in req.query_params.multi_items():
            norm_k = cls.normalize_string(k)
            norm_v = cls.normalize_string(v)
            query_items.append(f"{norm_k}={norm_v}")
        query_str = "&".join(sorted(query_items))

        # Extract and normalize monitored headers
        header_items = []
        for h_name, h_val in req.headers.items():
            if h_name.lower() in cls.MONITORED_HEADERS:
                norm_h = cls.normalize_string(h_val)
                header_items.append(f"{h_name.lower()}:{norm_h}")
        headers_str = ";".join(sorted(header_items))

        # Canonical representation representing the semantic surface area of the request
        canonical_components = [
            f"METHOD:{req.method}",
            f"PATH:{cls.normalize_string(req.url.path)}",
        ]
        if query_str:
            canonical_components.append(f"QUERY:{query_str}")
        if headers_str:
            canonical_components.append(f"HEADERS:{headers_str}")
        if normalized_body:
            canonical_components.append(f"BODY:{normalized_body}")

        canonical_payload = "\n".join(canonical_components)

        # Generate deterministic SHA-256 fingerprint for Redis caching
        payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

        return canonical_payload, payload_hash, raw_body

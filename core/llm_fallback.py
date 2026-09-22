import asyncio
import logging
from typing import Literal, Optional
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from config import settings

logger = logging.getLogger("WAF.LLMFallback")


class SecurityVerdict(BaseModel):
    """Structured response from the LLM threat evaluation engine."""
    verdict: Literal["BLOCK", "ALLOW"] = Field(
        ...,
        description="Final action: 'BLOCK' if payload demonstrates malicious intent or exploits, 'ALLOW' if benign."
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0."
    )
    attack_type: Optional[str] = Field(
        default=None,
        description="Identified attack vector: 'SQLi', 'XSS', 'Command Injection', 'Path Traversal', 'SSRF', 'SSTI', etc."
    )
    reasoning: str = Field(
        ...,
        description="Concise technical rationale detailing syntactic or semantic exploitation indicators."
    )


class LLMFallbackAnalyzer:
    """
    LangChain-powered cognitive evaluator using Google Gemini for boundary-range payloads.
    Performs real-time deep semantic inspection to distinguish true zero-days from false positives.
    Protected by strict async latency timeouts to prevent reverse proxy stalls.
    """

    SYSTEM_PROMPT = """You are an expert Application Security and Threat Intelligence Engineer acting as the fallback decision engine for a Semantic Web Application Firewall (WAF).

A vector similarity engine flagged an incoming HTTP request payload with an ambiguous similarity score ({similarity_score:.3f}).
Your duty is to conduct a zero-day vulnerability analysis and determine whether this request exhibits genuine malicious intent or is benign user input.

Inspection Criteria:
1. SQL Injection (SQLi): Union selects, boolean tautologies, time-based delays, comment truncations (-- , /* */), hex encodings.
2. Cross-Site Scripting (XSS): DOM/SVG payloads, event handler injections (onload, onerror), javascript: URIs, script injection.
3. Command/Code Injection (RCE): Shell metacharacters (; | & ` $() ), reverse shell vectors, process execution attempts.
4. Path Traversal & LFI: Directory climbing (../, %2e%2e%2f), access to sensitive files (/etc/passwd, win.ini).
5. SSRF / SSTI: Metadata endpoints (169.254.169.254), template delimiters ({{...}}, ${{...}}).
6. Evasion & Obfuscation: Nested encoding, polyglot patterns, abnormal character distributions.

Distinguish between legitimate content and weaponized payloads.
"""

    def __init__(self):
        self._chain = None
        self._initialize_chain()

    def _initialize_chain(self) -> None:
        """Configures the LangChain chat prompt and structured output schema with Gemini."""
        api_key = settings.effective_gemini_key
        if not api_key:
            logger.warning("GEMINI_API_KEY is not configured. LLM fallback will default to safe-block.")
            return

        try:
            llm = ChatGoogleGenerativeAI(
                model=settings.llm_model_name,
                google_api_key=api_key,
                temperature=0.0,
                max_retries=1,  # Do not loop-retry on 503/timeout
            )

            prompt = ChatPromptTemplate.from_messages([
                ("system", self.SYSTEM_PROMPT),
                ("human", "Inspect the following normalized HTTP request payload:\n\n```\n{payload}\n```\n\nProvide your security verdict.")
            ])

            self._chain = prompt | llm.with_structured_output(SecurityVerdict)
            logger.info(f"Initialized Gemini LLM fallback chain using {settings.llm_model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini LLM fallback chain: {e}")
            self._chain = None

    async def analyze(self, payload: str, similarity_score: float) -> SecurityVerdict:
        """
        Asynchronously evaluates boundary payload using Google Gemini.
        Guarded with an SLA timeout (4.0s) to keep WAF latency bounded.
        """
        if not self._chain:
            return SecurityVerdict(
                verdict="BLOCK",
                confidence=0.5,
                attack_type="Unverified_Boundary_Payload",
                reasoning="Gemini LLM engine unavailable; enforced fail-secure policy."
            )

        try:
            verdict: SecurityVerdict = await asyncio.wait_for(
                self._chain.ainvoke({
                    "payload": payload,
                    "similarity_score": similarity_score
                }),
                timeout=4.0
            )
            logger.info(f"Gemini Verdict: {verdict.verdict} | Type: {verdict.attack_type} | Conf: {verdict.confidence:.2f}")
            return verdict

        except asyncio.TimeoutError:
            logger.warning("Gemini LLM evaluation timed out after 4.0s SLA limit. Enforcing fail-secure BLOCK.")
            return SecurityVerdict(
                verdict="BLOCK",
                confidence=0.6,
                attack_type="SLA_Timeout_FailSecure",
                reasoning="LLM evaluation exceeded 4.0s proxy SLA limit. Enforced fail-secure block."
            )
        except Exception as e:
            logger.error(f"Gemini evaluation execution failed: {e}. Defaulting to fail-secure BLOCK.")
            return SecurityVerdict(
                verdict="BLOCK",
                confidence=0.5,
                attack_type="Evaluation_Error_FailSecure",
                reasoning=f"LLM evaluation encountered upstream service error: {str(e)[:100]}."
            )


# Singleton instance
llm_fallback_analyzer = LLMFallbackAnalyzer()

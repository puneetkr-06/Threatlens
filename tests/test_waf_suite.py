import asyncio
import os
import sys
import time
import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

WAF_BASE_URL = "http://localhost:8000"


async def run_security_tests():
    print("=" * 70)
    print("      SEMANTIC WAF AUTOMATED INTEGRATION & PENETRATION SUITE       ")
    print("=" * 70)

    async with httpx.AsyncClient(base_url=WAF_BASE_URL, timeout=30.0) as client:
        # 1. Benign Request
        print("\n[TEST 1] Sending Legitimate Benign Request...")
        start = time.perf_counter()
        res = await client.get("/api/products")
        duration = (time.perf_counter() - start) * 1000
        print(f"Status Code: {res.status_code} | Duration: {duration:.2f}ms")
        print(f"Response: {res.json()}")

        # 2. Classic SQL Injection Attack
        print("\n[TEST 2] Sending Weaponized SQL Injection Payload...")
        sqli_payload = {"username": "' OR '1'='1' --", "password": "password123"}
        start = time.perf_counter()
        res = await client.post("/api/login", json=sqli_payload)
        duration = (time.perf_counter() - start) * 1000
        print(f"Status Code: {res.status_code} (Expected 403 Forbidden) | Duration: {duration:.2f}ms")
        print(f"Security Alert Response: {res.json()}")

        # 3. High-Speed Cache Hit Verification
        print("\n[TEST 3] Re-sending Same SQL Injection Payload (Testing Redis Cache-Aside)...")
        start = time.perf_counter()
        res = await client.post("/api/login", json=sqli_payload)
        duration = (time.perf_counter() - start) * 1000
        print(f"Status Code: {res.status_code} | Duration: {duration:.2f}ms (Cache Hit Target < 5ms)")
        print(f"Response: {res.json()}")

        # 4. Cross-Site Scripting (XSS)
        print("\n[TEST 4] Sending Reflected XSS in Query Parameter...")
        xss_param = "<script>alert(document.cookie)</script>"
        start = time.perf_counter()
        res = await client.get(f"/api/user/profile?name={xss_param}")
        duration = (time.perf_counter() - start) * 1000
        print(f"Status Code: {res.status_code} (Expected 403 Forbidden) | Duration: {duration:.2f}ms")
        print(f"Response: {res.json()}")

        # 5. Remote Code Execution (RCE) / Command Injection
        print("\n[TEST 5] Sending Command Injection Payload...")
        cmd_payload = {"username": "admin; cat /etc/passwd", "password": "secret"}
        start = time.perf_counter()
        res = await client.post("/api/login", json=cmd_payload)
        duration = (time.perf_counter() - start) * 1000
        print(f"Status Code: {res.status_code} (Expected 403 Forbidden) | Duration: {duration:.2f}ms")
        print(f"Response: {res.json()}")

        # 6. Direct WAF Inspection Endpoint (Boundary Analysis)
        print("\n[TEST 6] Testing Direct Inspection API for Obfuscated / Boundary Payload...")
        inspect_data = {
            "payload": "SELECT * FROM inventory WHERE title LIKE '%12% OR true'",
            "method": "POST",
            "path": "/search"
        }
        res = await client.post("/waf/inspect", json=inspect_data)
        print(f"Inspection Result: {res.json()}")

    print("\n" + "=" * 70)
    print("                  TEST SUITE EXECUTION COMPLETE                    ")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_security_tests())

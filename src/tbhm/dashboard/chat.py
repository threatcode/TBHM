"""
AI Chat interface for TBHM.
"""

import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AIChatInterface:
    """Interactive AI chat for security queries."""

    def __init__(self, model: str = "llama3.2:3b"):
        self.model = model
        self.conversation_history = []

    async def query(
        self,
        question: str,
        context: Optional[Dict] = None,
    ) -> str:
        """
        Query AI with question and context.

        Args:
            question: User question
            context: Scan results and findings
        """
        try:
            import httpx

            system_prompt = self._build_system_prompt(context)

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    *self.conversation_history,
                    {"role": "user", "content": question},
                ],
                "stream": False,
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://localhost:11434/api/chat",
                    json=payload,
                    timeout=60,
                )

            if response.status_code == 200:
                data = response.json()
                answer = data.get("message", {}).get("content", "")
                return answer
        except Exception as e:
            logger.error(f"Error querying AI: {e}")
            return f"Error: {str(e)}"

        return "AI service unavailable"

    def _build_system_prompt(self, context: Optional[Dict]) -> str:
        """Build system prompt with context."""
        system = """You are a security expert assistant for TBHM (The Bug Hunter's Methodology).
You help analyze scan results, explain vulnerabilities, and provide remediation guidance."""

        if context:
            system += "\n\nContext data provided:\n"
            system += json.dumps(context, indent=2)[:2000]

        return system

    async def analyze_finding(
        self,
        finding: Dict,
    ) -> str:
        """Ask AI to analyze a specific finding."""
        question = f"Analyze this security finding: {json.dumps(finding)}"
        return await self.query(question)

    async def explain_vulnerability(
        self,
        vuln_type: str,
    ) -> str:
        """Explain a vulnerability type."""
        question = f"Explain {vuln_type} vulnerability, its impact, and how to fix it"
        return await self.query(question)

    async def suggest_tests(
        self,
        target_info: Dict,
    ) -> str:
        """Suggest security tests for a target."""
        question = f"What security tests would you recommend for: {json.dumps(target_info)}"
        return await self.query(question)


class TokenAnalyzer:
    """Analyze authentication tokens."""

    def __init__(self):
        self.token_patterns = {
            "jwt": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "bearer": r"Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "basic": r"Basic\s+[A-Za-z0-9+/=]+",
            "api_key": r"[Aa][Pp][Ii][Kk][Ee][Yy]\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
            "aws": r"AKIA[0-9A-Z]{16}",
            "github": r"ghp_[a-zA-Z0-9]{36}",
        }

    def extract_tokens(self, text: str) -> List[Dict]:
        """Extract tokens from text."""
        import re

        findings = []
        for token_type, pattern in self.token_patterns.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                token = match.group(0)
                if len(token) > 50:
                    token = token[:50] + "..."

                findings.append({
                    "type": token_type,
                    "token": token,
                    "position": match.start(),
                })

        return findings

    def analyze_token_security(
        self,
        token: str,
        token_type: str,
    ) -> Dict:
        """Analyze token for security issues."""
        analysis = {
            "type": token_type,
            "length_valid": False,
            "contains_sensitive": False,
            "recommendations": [],
        }

        if token_type == "jwt":
            try:
                parts = token.split(".")
                if len(parts) == 3:
                    analysis["length_valid"] = True
                    if "none" in parts[0].lower():
                        analysis["security_issue"] = "Weak algorithm"
            except Exception:
                pass

        analysis["recommendations"] = [
            "Use environment variables for secrets",
            "Rotate tokens regularly",
            "Implement token expiration",
        ]

        return analysis


async def run_ai_query(
    question: str,
    context: Optional[Dict] = None,
) -> dict:
    """Run AI query."""
    chat = AIChatInterface()

    answer = await chat.query(question, context)

    return {
        "question": question,
        "answer": answer,
        "model": chat.model,
    }
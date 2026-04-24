"""
Authenticated scanning and token analysis module.
"""

import base64
import hashlib
import json
import logging
import re
import subprocess
from typing import Dict, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
API_KEY_PATTERNS = [
    re.compile(r"[aA][pP][iI][-_]?[kK][eE][yY][[:space:]]*[:=][[:space:]]*['\"]?([A-Za-z0-9_-]{20,})['\"]?"),
    re.compile(r"[aA][pP][iI][-_]?[tT][oO][kK][eE][nN][[:space:]]*[:=][[:space:]]*['\"]?([A-Za-z0-9_-]{20,})['\"]?"),
    re.compile(r"[bB][eE][aA][rR][eE][rR][[:space:]]+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"),
]


class TokenAnalyzer:
    """Analyze authentication tokens."""

    def __init__(self):
        self.jwt_pattern = JWT_PATTERN
        self.api_key_patterns = API_KEY_PATTERNS

    def extract_tokens(self, content: str) -> List[Dict]:
        """Extract tokens from content."""
        tokens = []

        jwt_matches = self.jwt_pattern.findall(content)
        for match in jwt_matches:
            tokens.append({
                "type": "jwt",
                "value": match,
                "parsed": self.parse_jwt(match),
            })

        for pattern in self.api_key_patterns:
            matches = pattern.findall(content)
            for match in matches:
                tokens.append({
                    "type": "api_key",
                    "value": match[:10] + "***" if len(match) > 10 else match,
                    "hidden": True,
                })

        return tokens

    def parse_jwt(self, token: str) -> Dict:
        """Parse JWT token structure."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"valid": False}

            header = json.loads(base64.b64decode(parts[0] + "=="))
            payload = json.loads(base64.b64decode(parts[1] + "=="))

            exp = payload.get("exp")
            if exp:
                exp_time = datetime.fromtimestamp(exp)
                is_expired = exp_time < datetime.utcnow()
            else:
                is_expired = False

            return {
                "valid": True,
                "header": header,
                "payload": {k: v for k, v in payload.items() if k != "password"},
                "expired": is_expired,
                "expires_at": exp_time.isoformat() if exp else None,
            }

        except Exception as e:
            return {"valid": False, "error": str(e)}

    def analyze_token_claims(self, token: str) -> Dict:
        """Analyze JWT claims for security issues."""
        parsed = self.parse_jwt(token)

        if not parsed.get("valid"):
            return {"valid": False}

        claims = parsed.get("payload", {})
        issues = []

        if parsed.get("expired"):
            issues.append("Token is expired")

        if claims.get("iss") is None:
            issues.append("Missing issuer claim")

        if claims.get("aud") is None:
            issues.append("Missing audience claim")

        if claims.get("nbf") is None:
            issues.append("Missing not-before claim")

        iat = claims.get("iat")
        if iat and isinstance(iat, int):
            issued_at = datetime.fromtimestamp(iat)
            if issued_at > datetime.utcnow():
                issues.append("Token issued in the future")

        return {
            "issues": issues,
            "secure": len(issues) == 0,
            "claims": claims,
        }


class AuthenticatedScanner:
    """Perform authenticated vulnerability scans."""

    def __init__(self):
        self.token_analyzer = TokenAnalyzer()
        self.required_headers = [
            "Authorization",
            "X-API-Key",
            "X-Auth-Token",
        ]

    def test_authenticated(
        self,
        url: str,
        token: str,
        token_type: str = "bearer",
    ) -> Dict:
        """Test endpoint with authentication."""
        results = {
            "url": url,
            "authenticated": False,
            "access_level": None,
            "user_info": None,
        }

        headers = {}
        if token_type == "bearer":
            headers["Authorization"] = f"Bearer {token}"
        elif token_type == "api_key":
            headers["X-API-Key"] = token
        elif token_type == "basic":
            headers["Authorization"] = f"Basic {token}"

        try:
            cmd = [
                "curl", "-s", "-w", "\\n%{http_code}",
                "-H", "Accept: application/json",
            ]

            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

            cmd.append(url)

            proc_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if proc_result.returncode == 0:
                output = proc_result.stdout
                lines = output.strip().split("\n")
                status = int(lines[-1]) if lines else 0
                body = "\n".join(lines[:-1]) if len(lines) > 1 else output

                if status == 200:
                    results["authenticated"] = True
                    try:
                        data = json.loads(body)
                        results["user_info"] = data.get("user", data.get("email", {}))
                        results["access_level"] = data.get("role", "user")
                    except json.JSONDecodeError:
                        pass

                if status == 401:
                    results["error"] = "Unauthorized"
                elif status == 403:
                    results["error"] = "Forbidden"

        except Exception as e:
            logger.error(f"Error testing auth: {e}")

        return results

    def scan_private_endpoints(
        self,
        base_url: str,
        token: str,
        endpoints: List[str],
    ) -> Dict:
        """Scan private endpoints with auth."""
        results = {
            "base_url": base_url,
            "endpoints_scanned": 0,
            "private_found": 0,
            "results": [],
        }

        for endpoint in endpoints:
            url = f"{base_url}/{endpoint.lstrip('/')}"
            test_result = self.test_authenticated(url, token)

            results["results"].append(test_result)
            results["endpoints_scanned"] += 1

            if test_result.get("authenticated"):
                results["private_found"] += 1

        return results


class SessionManager:
    """Manage authentication sessions."""

    def __init__(self):
        self.sessions = {}
        self.max_sessions = 100

    def create_session(
        self,
        user_id: str,
        token: str,
        expires_in: int = 3600,
    ) -> str:
        """Create a new session."""
        session_id = hashlib.sha256(
            f"{user_id}:{token}:{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:32]

        self.sessions[session_id] = {
            "user_id": user_id,
            "token": token,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
        }

        if len(self.sessions) > self.max_sessions:
            oldest = min(self.sessions.items(), key=lambda x: x[1]["created_at"])
            del self.sessions[oldest[0]]

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details."""
        session = self.sessions.get(session_id)
        if not session:
            return None

        if session["expires_at"] < datetime.utcnow():
            del self.sessions[session_id]
            return None

        return session

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False


async def run_authenticated_scan(
    target_id: str,
    endpoints: List[str],
    token: str,
    token_type: str = "bearer",
) -> dict:
    """Run authenticated vulnerability scan."""
    scanner = AuthenticatedScanner()

    analyzer = TokenAnalyzer()
    token_analysis = analyzer.analyze_token_claims(token)

    all_results = []
    accessible_count = 0

    for endpoint in endpoints:
        result = scanner.test_authenticated(endpoint, token, token_type)
        all_results.append(result)

        if result.get("authenticated"):
            accessible_count += 1

    return {
        "target_id": target_id,
        "total_endpoints": len(endpoints),
        "accessible": accessible_count,
        "token_analysis": token_analysis,
        "results": all_results,
    }
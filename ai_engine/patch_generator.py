import os
from typing import Any, Dict

from openai import AsyncOpenAI


def _offline_patch(vuln_record: Dict[str, Any]) -> str:
    """Deterministic, signature-based remediation used when no API key is present."""
    return (
        "🛠️ [OFFLINE PATCH ENGINE RECOMMENDATION]\n"
        f"1. Restrict external access to port {vuln_record['port']} using host/network "
        f"firewall rules (iptables / ufw / security group).\n"
        f"2. Audit the process bound to that port -- banner observed: "
        f"'{vuln_record['banner_grabbed']}'.\n"
        f"3. Disable cleartext protocols where applicable and enforce TLS, matching the "
        f"{vuln_record['owasp_category']} guidance.\n"
        "4. If the service must remain internet-facing, place it behind an authenticated "
        "reverse proxy or VPN and enable rate limiting."
    )


async def generate_remediation_patch(
    vuln_record: Dict[str, Any],
    api_key: str = None,
    model: str = "gpt-4o",
) -> str:
    """
    Generates a tailored remediation patch for a single finding. Falls back
    to a deterministic offline recommendation if no API key is configured,
    or if the API call fails for any reason.
    """
    active_key = api_key or os.getenv("OPENAI_API_KEY", "")

    if not active_key:
        return _offline_patch(vuln_record)

    try:
        client = AsyncOpenAI(api_key=active_key)

        prompt = (
            "You are an elite DevSecOps automation security infrastructure engineer. "
            "Analyze the following vulnerability scan record discovered on an active port:\n"
            f"Port Probed: {vuln_record['port']}\n"
            f"Service Context: {vuln_record['service']}\n"
            f"Inferred Exposure: {vuln_record['vulnerability']}\n"
            f"OWASP Reference: {vuln_record['owasp_category']}\n"
            f"Banner Grabbed: {vuln_record['banner_grabbed']}\n\n"
            "Provide a direct, enterprise-grade remediation patch code block (Bash, Python, "
            "or firewall rule) and brief hardening steps to close this specific exposure."
        )

        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=600,
        )
        return response.choices[0].message.content
    except Exception as e:
        return (
            f"⚠️ [AI Generation Context Error]: Unable to fetch live model patch ({e}). "
            f"Falling back to offline recommendation.\n\n{_offline_patch(vuln_record)}"
        )

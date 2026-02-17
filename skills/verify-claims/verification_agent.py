#!/usr/bin/env python3
"""
Verification Agent (JVA) - Independent Fact-Checking for Threat Intelligence Claims

This module provides autonomous verification of IOCs, TTPs, and attribution claims
against authoritative source APIs. Designed for integration with MCP-based agent
architectures.

Author: CTI Agent
Version: 1.0.0

Usage:
    # Activate your virtual environment first
    aidev  # or: source ~/ai-dev/bin/activate

    # Install dependencies
    pip install httpx pydantic tenacity python-dotenv

    # Run standalone test
    python verification_agent.py
"""

import os
import json
import hashlib
import logging
from enum import Enum
from uuid import uuid4
from datetime import datetime, timedelta
from typing import Any, Optional
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel, Field
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("VerificationAgent")

# API Configuration - Load from environment
API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY", ""),
    "shodan": os.getenv("SHODAN_API_KEY", ""),
    "otx": os.getenv("OTX_API_KEY", ""),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", ""),
    "misp": os.getenv("MISP_API_KEY", ""),
}

API_ENDPOINTS = {
    "virustotal": "https://www.virustotal.com/api/v3",
    "shodan": "https://api.shodan.io",
    "otx": "https://otx.alienvault.com/api/v1",
    "abuseipdb": "https://api.abuseipdb.com/api/v2",
    "misp": os.getenv("MISP_URL", "https://your-misp-instance.local"),
    "urlhaus": "https://urlhaus-api.abuse.ch/v1",
}

# Verification timeout in seconds
REQUEST_TIMEOUT = 10.0

# Cache TTL in seconds (1 hour)
CACHE_TTL = 3600


# -----------------------------------------------------------------------------
# ENUMS & DATA MODELS
# -----------------------------------------------------------------------------


class VerificationStatus(str, Enum):
    """Verification confidence levels."""

    VERIFIED_HIGH = "VERIFIED_HIGH"
    VERIFIED_MEDIUM = "VERIFIED_MEDIUM"
    VERIFIED_LOW = "VERIFIED_LOW"
    UNVERIFIED = "UNVERIFIED"
    REFUTED = "REFUTED"


class MatchType(str, Enum):
    """Attribute comparison result types."""

    EXACT = "EXACT"
    PARTIAL = "PARTIAL"
    MISMATCH = "MISMATCH"
    MISSING = "MISSING"


class ClaimType(str, Enum):
    """Classification of intelligence claim types."""

    IOC = "IOC"
    TTP = "TTP"
    ATTRIBUTION = "ATTRIBUTION"
    TEMPORAL = "TEMPORAL"
    STATISTICAL = "STATISTICAL"


class SourcePlatform(str, Enum):
    """Supported source platforms for verification."""

    VIRUSTOTAL = "virustotal"
    SHODAN = "shodan"
    OTX = "otx"
    ABUSEIPDB = "abuseipdb"
    MISP = "misp"
    URLHAUS = "urlhaus"
    MITRE_ATTACK = "mitre_attack"


@dataclass
class AttributeCheck:
    """Result of a single attribute comparison."""

    attribute_name: str
    extracted_value: Any
    actual_value: Any
    match_type: MatchType

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "attribute_name": self.attribute_name,
            "extracted_value": self.extracted_value,
            "actual_value": self.actual_value,
            "match_type": self.match_type.value,
        }


@dataclass
class VerificationResult:
    """Complete verification result for a single claim."""

    claim_id: str
    original_claim: str
    claim_type: ClaimType
    source_platform: SourcePlatform
    object_identifier: str
    verification_status: VerificationStatus
    confidence_score: float
    attribute_checks: list[AttributeCheck] = field(default_factory=list)
    api_response_timestamp: str = ""
    api_http_status: int = 0
    retry_count: int = 0
    discrepancies: list[str] = field(default_factory=list)
    verification_notes: str = ""
    quarantine: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "claim_id": self.claim_id,
            "original_claim": self.original_claim,
            "claim_type": self.claim_type.value,
            "source_platform": self.source_platform.value,
            "object_identifier": self.object_identifier,
            "verification_status": self.verification_status.value,
            "confidence_score": self.confidence_score,
            "attribute_checks": [ac.to_dict() for ac in self.attribute_checks],
            "api_response_timestamp": self.api_response_timestamp,
            "api_http_status": self.api_http_status,
            "retry_count": self.retry_count,
            "discrepancies": self.discrepancies,
            "verification_notes": self.verification_notes,
            "quarantine": self.quarantine,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class Claim(BaseModel):
    """Input model for a claim to be verified."""

    claim_id: str = Field(default_factory=lambda: str(uuid4()))
    statement: str = Field(..., description="The verbatim claim from upstream agent")
    claim_type: ClaimType = Field(..., description="Classification of claim")
    source_platform: SourcePlatform = Field(..., description="Originating platform")
    object_identifier: str = Field(..., description="Hash, IP, domain, or ID")
    extracted_attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value pairs of attributes claimed by upstream agent",
    )


# -----------------------------------------------------------------------------
# VERIFICATION CACHE
# -----------------------------------------------------------------------------


class VerificationCache:
    """
    Simple in-memory cache for verification results.
    Ensures idempotency: same claim + source = same result within TTL.
    """

    def __init__(self, ttl_seconds: int = CACHE_TTL):
        self._cache: dict[str, tuple[VerificationResult, datetime]] = {}
        self._ttl = timedelta(seconds=ttl_seconds)

    def _make_key(self, source: str, identifier: str) -> str:
        """Generate cache key from source and identifier."""
        raw = f"{source}:{identifier}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def get(self, source: str, identifier: str) -> Optional[VerificationResult]:
        """Retrieve cached result if valid."""
        key = self._make_key(source, identifier)
        if key in self._cache:
            result, timestamp = self._cache[key]
            if datetime.utcnow() - timestamp < self._ttl:
                logger.debug(f"Cache hit for {source}:{identifier}")
                return result
            else:
                # Expired; remove from cache
                del self._cache[key]
        return None

    def set(self, source: str, identifier: str, result: VerificationResult) -> None:
        """Store verification result in cache."""
        key = self._make_key(source, identifier)
        self._cache[key] = (result, datetime.utcnow())
        logger.debug(f"Cached result for {source}:{identifier}")

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()


# Global cache instance
_cache = VerificationCache()


# -----------------------------------------------------------------------------
# API CLIENT WITH RETRY LOGIC
# -----------------------------------------------------------------------------


class APIClientError(Exception):
    """Custom exception for API client errors."""

    def __init__(self, message: str, status_code: int = 0, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=8),
    retry=retry_if_exception_type(APIClientError),
    before_sleep=lambda retry_state: logger.warning(
        f"Retry {retry_state.attempt_number}/3 after error"
    ),
)
async def make_api_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    params: Optional[dict] = None,
    json_body: Optional[dict] = None,
) -> tuple[int, dict]:
    """
    Execute API request with retry logic for transient failures.

    Returns:
        Tuple of (HTTP status code, response JSON dict)

    Raises:
        APIClientError: On non-retryable errors or after max retries
    """
    try:
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=REQUEST_TIMEOUT,
        )

        # Handle rate limiting (429) - retryable
        if response.status_code == 429:
            raise APIClientError(
                "Rate limited by API",
                status_code=429,
                retryable=True,
            )

        # Handle server errors (5xx) - retryable
        if 500 <= response.status_code < 600:
            raise APIClientError(
                f"Server error: {response.status_code}",
                status_code=response.status_code,
                retryable=True,
            )

        # Handle auth errors (401/403) - not retryable
        if response.status_code in (401, 403):
            raise APIClientError(
                f"Authentication failed: {response.status_code}",
                status_code=response.status_code,
                retryable=False,
            )

        # Parse JSON response
        try:
            data = response.json()
        except json.JSONDecodeError:
            data = {"raw_text": response.text}

        return response.status_code, data

    except httpx.TimeoutException:
        raise APIClientError("Request timeout", status_code=0, retryable=True)
    except httpx.RequestError as e:
        raise APIClientError(f"Request failed: {e}", status_code=0, retryable=True)


# -----------------------------------------------------------------------------
# SOURCE-SPECIFIC VERIFICATION HANDLERS
# -----------------------------------------------------------------------------


async def verify_virustotal_hash(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
) -> tuple[int, list[AttributeCheck], dict]:
    """
    Verify a file hash against VirusTotal API.

    Args:
        client: HTTP client instance
        identifier: SHA256, SHA1, or MD5 hash
        extracted_attrs: Attributes claimed by upstream agent

    Returns:
        Tuple of (HTTP status, attribute checks, raw response)
    """
    url = f"{API_ENDPOINTS['virustotal']}/files/{identifier}"
    headers = {"x-apikey": API_KEYS["virustotal"]}

    status_code, data = await make_api_request(client, "GET", url, headers)

    attribute_checks = []
    if status_code == 200 and "data" in data:
        attrs = data["data"].get("attributes", {})

        # Check detection statistics
        if "detection_count" in extracted_attrs:
            stats = attrs.get("last_analysis_stats", {})
            actual_malicious = stats.get("malicious", 0)
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="detection_count",
                    extracted_value=extracted_attrs["detection_count"],
                    actual_value=actual_malicious,
                    match_type=_compare_numeric(
                        extracted_attrs["detection_count"],
                        actual_malicious,
                        tolerance=2,  # Allow ±2 detection variance
                    ),
                )
            )

        # Check first submission date
        if "first_seen" in extracted_attrs:
            actual_first = attrs.get("first_submission_date")
            if actual_first:
                # Convert epoch to ISO date string
                actual_date = datetime.utcfromtimestamp(actual_first).strftime(
                    "%Y-%m-%d"
                )
                attribute_checks.append(
                    AttributeCheck(
                        attribute_name="first_seen",
                        extracted_value=extracted_attrs["first_seen"],
                        actual_value=actual_date,
                        match_type=_compare_dates(
                            extracted_attrs["first_seen"],
                            actual_date,
                            tolerance_days=1,
                        ),
                    )
                )

        # Check file names
        if "file_name" in extracted_attrs:
            actual_names = attrs.get("names", [])
            match_type = (
                MatchType.EXACT
                if extracted_attrs["file_name"] in actual_names
                else MatchType.MISMATCH
            )
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="file_name",
                    extracted_value=extracted_attrs["file_name"],
                    actual_value=actual_names[:5],  # Limit to first 5 names
                    match_type=match_type,
                )
            )

        # Check file type
        if "file_type" in extracted_attrs:
            actual_type = attrs.get("type_description", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="file_type",
                    extracted_value=extracted_attrs["file_type"],
                    actual_value=actual_type,
                    match_type=(
                        MatchType.EXACT
                        if extracted_attrs["file_type"].lower() in actual_type.lower()
                        else MatchType.PARTIAL
                        if any(
                            word in actual_type.lower()
                            for word in extracted_attrs["file_type"].lower().split()
                        )
                        else MatchType.MISMATCH
                    ),
                )
            )

    return status_code, attribute_checks, data


async def verify_virustotal_ip(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
) -> tuple[int, list[AttributeCheck], dict]:
    """Verify an IP address against VirusTotal API."""
    url = f"{API_ENDPOINTS['virustotal']}/ip_addresses/{identifier}"
    headers = {"x-apikey": API_KEYS["virustotal"]}

    status_code, data = await make_api_request(client, "GET", url, headers)

    attribute_checks = []
    if status_code == 200 and "data" in data:
        attrs = data["data"].get("attributes", {})

        # Check ASN owner
        if "as_owner" in extracted_attrs:
            actual_owner = attrs.get("as_owner", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="as_owner",
                    extracted_value=extracted_attrs["as_owner"],
                    actual_value=actual_owner,
                    match_type=_compare_strings(
                        extracted_attrs["as_owner"],
                        actual_owner,
                    ),
                )
            )

        # Check country
        if "country" in extracted_attrs:
            actual_country = attrs.get("country", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="country",
                    extracted_value=extracted_attrs["country"],
                    actual_value=actual_country,
                    match_type=(
                        MatchType.EXACT
                        if extracted_attrs["country"].upper() == actual_country.upper()
                        else MatchType.MISMATCH
                    ),
                )
            )

        # Check malicious votes
        if "malicious_count" in extracted_attrs:
            stats = attrs.get("last_analysis_stats", {})
            actual_malicious = stats.get("malicious", 0)
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="malicious_count",
                    extracted_value=extracted_attrs["malicious_count"],
                    actual_value=actual_malicious,
                    match_type=_compare_numeric(
                        extracted_attrs["malicious_count"],
                        actual_malicious,
                        tolerance=2,
                    ),
                )
            )

    return status_code, attribute_checks, data


async def verify_virustotal_domain(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
) -> tuple[int, list[AttributeCheck], dict]:
    """Verify a domain against VirusTotal API."""
    url = f"{API_ENDPOINTS['virustotal']}/domains/{identifier}"
    headers = {"x-apikey": API_KEYS["virustotal"]}

    status_code, data = await make_api_request(client, "GET", url, headers)

    attribute_checks = []
    if status_code == 200 and "data" in data:
        attrs = data["data"].get("attributes", {})

        # Check registrar
        if "registrar" in extracted_attrs:
            actual_registrar = attrs.get("registrar", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="registrar",
                    extracted_value=extracted_attrs["registrar"],
                    actual_value=actual_registrar,
                    match_type=_compare_strings(
                        extracted_attrs["registrar"],
                        actual_registrar,
                    ),
                )
            )

        # Check creation date
        if "creation_date" in extracted_attrs:
            actual_creation = attrs.get("creation_date")
            if actual_creation:
                actual_date = datetime.utcfromtimestamp(actual_creation).strftime(
                    "%Y-%m-%d"
                )
                attribute_checks.append(
                    AttributeCheck(
                        attribute_name="creation_date",
                        extracted_value=extracted_attrs["creation_date"],
                        actual_value=actual_date,
                        match_type=_compare_dates(
                            extracted_attrs["creation_date"],
                            actual_date,
                            tolerance_days=1,
                        ),
                    )
                )

    return status_code, attribute_checks, data


async def verify_shodan_ip(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
) -> tuple[int, list[AttributeCheck], dict]:
    """Verify an IP address against Shodan API."""
    url = f"{API_ENDPOINTS['shodan']}/shodan/host/{identifier}"
    params = {"key": API_KEYS["shodan"]}

    status_code, data = await make_api_request(client, "GET", url, {}, params=params)

    attribute_checks = []
    if status_code == 200:
        # Check open ports
        if "ports" in extracted_attrs:
            actual_ports = data.get("ports", [])
            extracted_ports = set(extracted_attrs["ports"])
            actual_ports_set = set(actual_ports)
            overlap = extracted_ports & actual_ports_set
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="ports",
                    extracted_value=list(extracted_ports),
                    actual_value=actual_ports,
                    match_type=(
                        MatchType.EXACT
                        if extracted_ports == actual_ports_set
                        else MatchType.PARTIAL
                        if overlap
                        else MatchType.MISMATCH
                    ),
                )
            )

        # Check organization
        if "org" in extracted_attrs:
            actual_org = data.get("org", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="org",
                    extracted_value=extracted_attrs["org"],
                    actual_value=actual_org,
                    match_type=_compare_strings(extracted_attrs["org"], actual_org),
                )
            )

        # Check vulnerabilities
        if "vulns" in extracted_attrs:
            actual_vulns = data.get("vulns", [])
            extracted_vulns = set(extracted_attrs["vulns"])
            actual_vulns_set = set(actual_vulns)
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="vulns",
                    extracted_value=list(extracted_vulns),
                    actual_value=actual_vulns,
                    match_type=(
                        MatchType.EXACT
                        if extracted_vulns == actual_vulns_set
                        else MatchType.PARTIAL
                        if extracted_vulns & actual_vulns_set
                        else MatchType.MISMATCH
                    ),
                )
            )

    return status_code, attribute_checks, data


async def verify_abuseipdb(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
) -> tuple[int, list[AttributeCheck], dict]:
    """Verify an IP address against AbuseIPDB API."""
    url = f"{API_ENDPOINTS['abuseipdb']}/check"
    headers = {"Key": API_KEYS["abuseipdb"], "Accept": "application/json"}
    params = {"ipAddress": identifier, "maxAgeInDays": 90}

    status_code, data = await make_api_request(
        client, "GET", url, headers, params=params
    )

    attribute_checks = []
    if status_code == 200 and "data" in data:
        result = data["data"]

        # Check abuse confidence score
        if "abuse_score" in extracted_attrs:
            actual_score = result.get("abuseConfidenceScore", 0)
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="abuse_score",
                    extracted_value=extracted_attrs["abuse_score"],
                    actual_value=actual_score,
                    match_type=_compare_numeric(
                        extracted_attrs["abuse_score"],
                        actual_score,
                        tolerance=5,  # ±5% tolerance for abuse score
                    ),
                )
            )

        # Check total reports
        if "total_reports" in extracted_attrs:
            actual_reports = result.get("totalReports", 0)
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="total_reports",
                    extracted_value=extracted_attrs["total_reports"],
                    actual_value=actual_reports,
                    match_type=_compare_numeric(
                        extracted_attrs["total_reports"],
                        actual_reports,
                        tolerance=5,
                    ),
                )
            )

        # Check country
        if "country" in extracted_attrs:
            actual_country = result.get("countryCode", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="country",
                    extracted_value=extracted_attrs["country"],
                    actual_value=actual_country,
                    match_type=(
                        MatchType.EXACT
                        if extracted_attrs["country"].upper() == actual_country.upper()
                        else MatchType.MISMATCH
                    ),
                )
            )

    return status_code, attribute_checks, data


async def verify_otx_pulse(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
) -> tuple[int, list[AttributeCheck], dict]:
    """Verify a pulse against AlienVault OTX API."""
    url = f"{API_ENDPOINTS['otx']}/pulses/{identifier}"
    headers = {"X-OTX-API-KEY": API_KEYS["otx"]}

    status_code, data = await make_api_request(client, "GET", url, headers)

    attribute_checks = []
    if status_code == 200:
        # Check pulse name
        if "name" in extracted_attrs:
            actual_name = data.get("name", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="name",
                    extracted_value=extracted_attrs["name"],
                    actual_value=actual_name,
                    match_type=_compare_strings(extracted_attrs["name"], actual_name),
                )
            )

        # Check indicator count
        if "indicator_count" in extracted_attrs:
            actual_count = len(data.get("indicators", []))
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="indicator_count",
                    extracted_value=extracted_attrs["indicator_count"],
                    actual_value=actual_count,
                    match_type=_compare_numeric(
                        extracted_attrs["indicator_count"],
                        actual_count,
                        tolerance=5,
                    ),
                )
            )

        # Check creation date
        if "created" in extracted_attrs:
            actual_created = data.get("created", "")[:10]  # Extract date portion
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="created",
                    extracted_value=extracted_attrs["created"],
                    actual_value=actual_created,
                    match_type=_compare_dates(
                        extracted_attrs["created"],
                        actual_created,
                        tolerance_days=1,
                    ),
                )
            )

    return status_code, attribute_checks, data


async def verify_urlhaus(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
    identifier_type: str = "url",
) -> tuple[int, list[AttributeCheck], dict]:
    """Verify a URL or payload hash against URLhaus API."""
    if identifier_type == "hash":
        url = f"{API_ENDPOINTS['urlhaus']}/payload/"
        payload = {"sha256_hash": identifier}
    else:
        url = f"{API_ENDPOINTS['urlhaus']}/url/"
        payload = {"url": identifier}

    status_code, data = await make_api_request(
        client,
        "POST",
        url,
        {"Content-Type": "application/x-www-form-urlencoded"},
        json_body=payload,
    )

    attribute_checks = []
    if data.get("query_status") == "ok":
        # Check threat type
        if "threat" in extracted_attrs:
            actual_threat = data.get("threat", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="threat",
                    extracted_value=extracted_attrs["threat"],
                    actual_value=actual_threat,
                    match_type=_compare_strings(
                        extracted_attrs["threat"], actual_threat
                    ),
                )
            )

        # Check URL status
        if "url_status" in extracted_attrs:
            actual_status = data.get("url_status", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="url_status",
                    extracted_value=extracted_attrs["url_status"],
                    actual_value=actual_status,
                    match_type=(
                        MatchType.EXACT
                        if extracted_attrs["url_status"].lower()
                        == actual_status.lower()
                        else MatchType.MISMATCH
                    ),
                )
            )

        # Check tags
        if "tags" in extracted_attrs:
            actual_tags = data.get("tags", [])
            extracted_tags = set(extracted_attrs["tags"])
            actual_tags_set = set(actual_tags) if actual_tags else set()
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="tags",
                    extracted_value=list(extracted_tags),
                    actual_value=actual_tags,
                    match_type=(
                        MatchType.EXACT
                        if extracted_tags == actual_tags_set
                        else MatchType.PARTIAL
                        if extracted_tags & actual_tags_set
                        else MatchType.MISMATCH
                    ),
                )
            )

    return status_code, attribute_checks, data


async def verify_misp_event(
    client: httpx.AsyncClient,
    identifier: str,
    extracted_attrs: dict[str, Any],
) -> tuple[int, list[AttributeCheck], dict]:
    """Verify an event against MISP instance."""
    url = f"{API_ENDPOINTS['misp']}/events/view/{identifier}"
    headers = {
        "Authorization": API_KEYS["misp"],
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    status_code, data = await make_api_request(client, "GET", url, headers)

    attribute_checks = []
    if status_code == 200 and "Event" in data:
        event = data["Event"]

        # Check event info/title
        if "info" in extracted_attrs:
            actual_info = event.get("info", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="info",
                    extracted_value=extracted_attrs["info"],
                    actual_value=actual_info,
                    match_type=_compare_strings(extracted_attrs["info"], actual_info),
                )
            )

        # Check event date
        if "date" in extracted_attrs:
            actual_date = event.get("date", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="date",
                    extracted_value=extracted_attrs["date"],
                    actual_value=actual_date,
                    match_type=_compare_dates(
                        extracted_attrs["date"],
                        actual_date,
                        tolerance_days=1,
                    ),
                )
            )

        # Check threat level
        if "threat_level" in extracted_attrs:
            actual_level = event.get("threat_level_id", "")
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="threat_level",
                    extracted_value=str(extracted_attrs["threat_level"]),
                    actual_value=actual_level,
                    match_type=(
                        MatchType.EXACT
                        if str(extracted_attrs["threat_level"]) == actual_level
                        else MatchType.MISMATCH
                    ),
                )
            )

        # Check attribute count
        if "attribute_count" in extracted_attrs:
            actual_count = len(event.get("Attribute", []))
            attribute_checks.append(
                AttributeCheck(
                    attribute_name="attribute_count",
                    extracted_value=extracted_attrs["attribute_count"],
                    actual_value=actual_count,
                    match_type=_compare_numeric(
                        extracted_attrs["attribute_count"],
                        actual_count,
                        tolerance=5,
                    ),
                )
            )

    return status_code, attribute_checks, data


# -----------------------------------------------------------------------------
# COMPARISON UTILITIES
# -----------------------------------------------------------------------------


def _compare_numeric(
    extracted: Any,
    actual: Any,
    tolerance: int = 0,
) -> MatchType:
    """Compare numeric values with optional tolerance."""
    try:
        ext_val = int(extracted)
        act_val = int(actual)
        if ext_val == act_val:
            return MatchType.EXACT
        elif abs(ext_val - act_val) <= tolerance:
            return MatchType.PARTIAL
        else:
            return MatchType.MISMATCH
    except (ValueError, TypeError):
        return MatchType.MISMATCH


def _compare_strings(extracted: str, actual: str) -> MatchType:
    """Compare string values with fuzzy matching."""
    if not extracted or not actual:
        return MatchType.MISSING if not actual else MatchType.MISMATCH

    ext_lower = extracted.lower().strip()
    act_lower = actual.lower().strip()

    if ext_lower == act_lower:
        return MatchType.EXACT
    elif ext_lower in act_lower or act_lower in ext_lower:
        return MatchType.PARTIAL
    else:
        return MatchType.MISMATCH


def _compare_dates(
    extracted: str,
    actual: str,
    tolerance_days: int = 1,
) -> MatchType:
    """Compare date strings with tolerance."""
    try:
        # Handle various date formats
        for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%m/%d/%Y"]:
            try:
                ext_date = datetime.strptime(extracted[:10], fmt)
                break
            except ValueError:
                continue
        else:
            return MatchType.MISMATCH

        for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%m/%d/%Y"]:
            try:
                act_date = datetime.strptime(actual[:10], fmt)
                break
            except ValueError:
                continue
        else:
            return MatchType.MISMATCH

        delta = abs((ext_date - act_date).days)
        if delta == 0:
            return MatchType.EXACT
        elif delta <= tolerance_days:
            return MatchType.PARTIAL
        else:
            return MatchType.MISMATCH

    except Exception:
        return MatchType.MISMATCH


# -----------------------------------------------------------------------------
# CONFIDENCE SCORING
# -----------------------------------------------------------------------------


def calculate_verification_status(
    attribute_checks: list[AttributeCheck],
    http_status: int,
) -> tuple[VerificationStatus, float]:
    """
    Calculate verification status and confidence score based on attribute checks.

    Args:
        attribute_checks: List of attribute comparison results
        http_status: HTTP status code from API response

    Returns:
        Tuple of (VerificationStatus, confidence_score 0.0-1.0)
    """
    if http_status == 404:
        return VerificationStatus.REFUTED, 0.0

    if http_status != 200 or not attribute_checks:
        return VerificationStatus.UNVERIFIED, 0.25

    exact_count = sum(1 for ac in attribute_checks if ac.match_type == MatchType.EXACT)
    partial_count = sum(
        1 for ac in attribute_checks if ac.match_type == MatchType.PARTIAL
    )
    mismatch_count = sum(
        1 for ac in attribute_checks if ac.match_type == MatchType.MISMATCH
    )
    total_checks = len(attribute_checks)

    # Any mismatch on key attribute = REFUTED
    if mismatch_count > 0:
        confidence = max(0.0, (exact_count + partial_count * 0.5) / total_checks * 0.3)
        return VerificationStatus.REFUTED, confidence

    # Calculate base confidence
    confidence = (exact_count + partial_count * 0.7) / total_checks

    # Determine status tier
    if exact_count >= 3:
        return VerificationStatus.VERIFIED_HIGH, min(1.0, confidence)
    elif exact_count >= 1 or (exact_count + partial_count) >= 3:
        return VerificationStatus.VERIFIED_MEDIUM, min(0.85, confidence)
    elif partial_count >= 1:
        return VerificationStatus.VERIFIED_LOW, min(0.6, confidence)
    else:
        return VerificationStatus.UNVERIFIED, 0.25


# -----------------------------------------------------------------------------
# MAIN VERIFICATION DISPATCHER
# -----------------------------------------------------------------------------


def _detect_identifier_type(identifier: str) -> str:
    """Detect the type of identifier (hash, IP, domain, etc.)."""
    import re

    # SHA256
    if re.match(r"^[a-fA-F0-9]{64}$", identifier):
        return "sha256"
    # SHA1
    if re.match(r"^[a-fA-F0-9]{40}$", identifier):
        return "sha1"
    # MD5
    if re.match(r"^[a-fA-F0-9]{32}$", identifier):
        return "md5"
    # IPv4
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", identifier):
        return "ipv4"
    # IPv6 (simplified check)
    if ":" in identifier and re.match(r"^[a-fA-F0-9:]+$", identifier):
        return "ipv6"
    # URL
    if identifier.startswith(("http://", "https://")):
        return "url"
    # Domain (basic check)
    if "." in identifier and not identifier.startswith(("http://", "https://")):
        return "domain"
    # UUID
    if re.match(
        r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
        identifier,
    ):
        return "uuid"

    return "unknown"


async def verify_claim(claim: Claim) -> VerificationResult:
    """
    Main entry point for verifying a single claim.

    This function routes the claim to the appropriate source-specific
    verification handler based on the source platform.

    Args:
        claim: The claim to verify

    Returns:
        VerificationResult with status, confidence, and attribute checks
    """
    # Check cache first
    cached = _cache.get(claim.source_platform.value, claim.object_identifier)
    if cached:
        logger.info(f"Returning cached result for {claim.claim_id}")
        return cached

    logger.info(
        f"Verifying claim {claim.claim_id}: {claim.source_platform.value} / {claim.object_identifier}"
    )

    async with httpx.AsyncClient() as client:
        try:
            status_code = 0
            attribute_checks: list[AttributeCheck] = []
            raw_response: dict = {}
            retry_count = 0
            identifier_type = _detect_identifier_type(claim.object_identifier)

            # Route to appropriate handler based on source platform
            if claim.source_platform == SourcePlatform.VIRUSTOTAL:
                if identifier_type in ("sha256", "sha1", "md5"):
                    (
                        status_code,
                        attribute_checks,
                        raw_response,
                    ) = await verify_virustotal_hash(
                        client,
                        claim.object_identifier,
                        claim.extracted_attributes,
                    )
                elif identifier_type in ("ipv4", "ipv6"):
                    (
                        status_code,
                        attribute_checks,
                        raw_response,
                    ) = await verify_virustotal_ip(
                        client,
                        claim.object_identifier,
                        claim.extracted_attributes,
                    )
                elif identifier_type == "domain":
                    (
                        status_code,
                        attribute_checks,
                        raw_response,
                    ) = await verify_virustotal_domain(
                        client,
                        claim.object_identifier,
                        claim.extracted_attributes,
                    )
                else:
                    logger.warning(f"Unsupported VT identifier type: {identifier_type}")
                    status_code = 400

            elif claim.source_platform == SourcePlatform.SHODAN:
                status_code, attribute_checks, raw_response = await verify_shodan_ip(
                    client,
                    claim.object_identifier,
                    claim.extracted_attributes,
                )

            elif claim.source_platform == SourcePlatform.ABUSEIPDB:
                status_code, attribute_checks, raw_response = await verify_abuseipdb(
                    client,
                    claim.object_identifier,
                    claim.extracted_attributes,
                )

            elif claim.source_platform == SourcePlatform.OTX:
                status_code, attribute_checks, raw_response = await verify_otx_pulse(
                    client,
                    claim.object_identifier,
                    claim.extracted_attributes,
                )

            elif claim.source_platform == SourcePlatform.URLHAUS:
                id_type = "hash" if identifier_type in ("sha256", "md5") else "url"
                status_code, attribute_checks, raw_response = await verify_urlhaus(
                    client,
                    claim.object_identifier,
                    claim.extracted_attributes,
                    identifier_type=id_type,
                )

            elif claim.source_platform == SourcePlatform.MISP:
                status_code, attribute_checks, raw_response = await verify_misp_event(
                    client,
                    claim.object_identifier,
                    claim.extracted_attributes,
                )

            else:
                logger.warning(f"Unsupported platform: {claim.source_platform}")
                status_code = 501  # Not Implemented

            # Calculate verification status and confidence
            verification_status, confidence_score = calculate_verification_status(
                attribute_checks,
                status_code,
            )

            # Collect discrepancies
            discrepancies = [
                f"{ac.attribute_name}: extracted={ac.extracted_value}, actual={ac.actual_value}"
                for ac in attribute_checks
                if ac.match_type in (MatchType.MISMATCH, MatchType.PARTIAL)
            ]

            # Build result
            result = VerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.statement,
                claim_type=claim.claim_type,
                source_platform=claim.source_platform,
                object_identifier=claim.object_identifier,
                verification_status=verification_status,
                confidence_score=confidence_score,
                attribute_checks=attribute_checks,
                api_response_timestamp=datetime.utcnow().isoformat() + "Z",
                api_http_status=status_code,
                retry_count=retry_count,
                discrepancies=discrepancies,
                verification_notes="",
                quarantine=(verification_status == VerificationStatus.REFUTED),
            )

            # Cache the result
            _cache.set(claim.source_platform.value, claim.object_identifier, result)

            return result

        except APIClientError as e:
            logger.error(f"API error verifying claim {claim.claim_id}: {e}")
            return VerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.statement,
                claim_type=claim.claim_type,
                source_platform=claim.source_platform,
                object_identifier=claim.object_identifier,
                verification_status=VerificationStatus.UNVERIFIED,
                confidence_score=0.25,
                api_http_status=e.status_code,
                verification_notes=f"API error: {e}",
                quarantine=False,
            )

        except Exception as e:
            logger.exception(f"Unexpected error verifying claim {claim.claim_id}")
            return VerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.statement,
                claim_type=claim.claim_type,
                source_platform=claim.source_platform,
                object_identifier=claim.object_identifier,
                verification_status=VerificationStatus.UNVERIFIED,
                confidence_score=0.0,
                verification_notes=f"Unexpected error: {e}",
                quarantine=False,
            )


async def verify_claims_batch(claims: list[Claim]) -> list[VerificationResult]:
    """
    Verify multiple claims in parallel.

    Args:
        claims: List of claims to verify

    Returns:
        List of verification results in same order as input
    """
    import asyncio

    logger.info(f"Starting batch verification of {len(claims)} claims")
    tasks = [verify_claim(claim) for claim in claims]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Convert exceptions to UNVERIFIED results
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Batch verification error for claim {i}: {result}")
            processed_results.append(
                VerificationResult(
                    claim_id=claims[i].claim_id,
                    original_claim=claims[i].statement,
                    claim_type=claims[i].claim_type,
                    source_platform=claims[i].source_platform,
                    object_identifier=claims[i].object_identifier,
                    verification_status=VerificationStatus.UNVERIFIED,
                    confidence_score=0.0,
                    verification_notes=f"Batch error: {result}",
                    quarantine=False,
                )
            )
        else:
            processed_results.append(result)

    return processed_results


# -----------------------------------------------------------------------------
# PARENT AGENT HANDOFF INTERFACE
# -----------------------------------------------------------------------------


def apply_confidence_weights(
    results: list[VerificationResult],
) -> list[dict[str, Any]]:
    """
    Apply confidence multipliers for parent agent consumption.

    Returns list of claims with weighted confidence for downstream processing.
    """
    weight_map = {
        VerificationStatus.VERIFIED_HIGH: 1.0,
        VerificationStatus.VERIFIED_MEDIUM: 0.75,
        VerificationStatus.VERIFIED_LOW: 0.5,
        VerificationStatus.UNVERIFIED: 0.25,
        VerificationStatus.REFUTED: 0.0,
    }

    weighted_results = []
    for result in results:
        multiplier = weight_map.get(result.verification_status, 0.0)
        weighted_results.append(
            {
                "claim_id": result.claim_id,
                "original_claim": result.original_claim,
                "verification_status": result.verification_status.value,
                "raw_confidence": result.confidence_score,
                "weight_multiplier": multiplier,
                "weighted_confidence": result.confidence_score * multiplier,
                "include_in_output": result.verification_status
                != VerificationStatus.REFUTED,
                "prefix_required": (
                    "[UNVERIFIED] "
                    if result.verification_status == VerificationStatus.UNVERIFIED
                    else ""
                ),
                "quarantine": result.quarantine,
            }
        )

    return weighted_results


def generate_verification_report(results: list[VerificationResult]) -> str:
    """
    Generate a human-readable verification summary report.

    Args:
        results: List of verification results

    Returns:
        Formatted markdown report
    """
    total = len(results)
    by_status = {}
    for r in results:
        status = r.verification_status.value
        by_status[status] = by_status.get(status, 0) + 1

    report_lines = [
        "# Verification Summary Report",
        f"\n**Total Claims Verified:** {total}",
        f"**Timestamp:** {datetime.utcnow().isoformat()}Z",
        "\n## Status Distribution\n",
    ]

    for status, count in sorted(by_status.items()):
        pct = (count / total * 100) if total > 0 else 0
        report_lines.append(f"- **{status}:** {count} ({pct:.1f}%)")

    # List quarantined claims
    quarantined = [r for r in results if r.quarantine]
    if quarantined:
        report_lines.append("\n## Quarantined Claims (Require Review)\n")
        for r in quarantined:
            report_lines.append(f"- `{r.claim_id}`: {r.original_claim[:80]}...")
            if r.discrepancies:
                report_lines.append(f"  - Discrepancies: {'; '.join(r.discrepancies)}")

    # List unverified claims
    unverified = [
        r for r in results if r.verification_status == VerificationStatus.UNVERIFIED
    ]
    if unverified:
        report_lines.append("\n## Unverified Claims (Flagged for Follow-up)\n")
        for r in unverified:
            report_lines.append(f"- `{r.claim_id}`: {r.original_claim[:80]}...")
            report_lines.append(f"  - Note: {r.verification_notes or 'No details'}")

    return "\n".join(report_lines)


# -----------------------------------------------------------------------------
# CLI INTERFACE FOR STANDALONE TESTING
# -----------------------------------------------------------------------------


async def main():
    """CLI entry point for testing verification agent."""
    # Example test claims
    test_claims = [
        Claim(
            statement="SHA256 abc123... has 45 detections on VirusTotal",
            claim_type=ClaimType.IOC,
            source_platform=SourcePlatform.VIRUSTOTAL,
            object_identifier="a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
            extracted_attributes={
                "detection_count": 45,
                "first_seen": "2024-01-15",
            },
        ),
        Claim(
            statement="IP 8.8.8.8 belongs to Google",
            claim_type=ClaimType.IOC,
            source_platform=SourcePlatform.VIRUSTOTAL,
            object_identifier="8.8.8.8",
            extracted_attributes={
                "as_owner": "Google LLC",
                "country": "US",
            },
        ),
    ]

    print("=" * 60)
    print("VERIFICATION AGENT - TEST RUN")
    print("=" * 60)

    results = await verify_claims_batch(test_claims)

    for result in results:
        print(f"\n{'-' * 40}")
        print(result.to_json())

    print(f"\n{'=' * 60}")
    print(generate_verification_report(results))

    # Output weighted results for parent agent
    print(f"\n{'=' * 60}")
    print("WEIGHTED RESULTS FOR PARENT AGENT:")
    print(json.dumps(apply_confidence_weights(results), indent=2))


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())

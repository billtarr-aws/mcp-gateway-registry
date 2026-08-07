"""
Anypoint Exchange (MuleSoft Agent Fabric) federation client.

Fetches MCP server and A2A agent assets from Anypoint Exchange and transforms
them to the gateway's internal format.

Two properties of Exchange shape this client, both verified against a live
organization rather than inferred from documentation:

1. Descriptor fidelity is type-dependent. An ``mcp`` asset's ``mcp-metadata``
   file carries the full contract - tools with JSON Schemas, capabilities,
   transport kind, protocolVersion. An ``a2a`` or ``agent`` asset's
   ``agent-metadata`` carries provenance only (botDefinitionId, platform,
   status). This is why ``asset_types`` defaults to the protocol-typed assets.

2. The endpoint comes from one of two places, and NEITHER is the transport
   descriptor. ``mcp-metadata.transport`` gives a path only
   (``{"kind": "streamableHttp", "path": "/mcp"}``). Resolution order:

   a. The asset record's ``attributes`` list may carry a ``url`` key holding a
      COMPLETE endpoint - e.g. ``https://mapstools.googleapis.com/mcp``. Present
      when the scanner that imported the asset knew the deployed endpoint (2 of 3
      ``mcp`` assets in the sample org; no ``a2a`` asset).
   b. **API Manager**, a sibling Anypoint service, holds the deployed API
      instance and its ``endpoint.uri``. This is where the endpoint lives for
      everything else, and it required no guessing: an API instance carries the
      Exchange coordinates (``groupId``/``assetId``/``assetVersion``) verbatim,
      so the join is an explicit foreign key.

3. Exchange asset to API instance is **one-to-many**, and instances are scoped
   per ENVIRONMENT while Exchange assets are not. In the sample org, the single
   asset ``omni-gateway-orders-mcp-spec`` v1.0.1 has THREE API Manager instances
   with three different endpoints and policy sets. So one Exchange asset can
   yield several registry records, and an import that ignores environment would
   silently mix sandbox and production endpoints.

API documentation: https://docs.mulesoft.com/exchange/
The Exchange asset listing (Platform API v2) is undocumented but stable in
practice. The API Manager endpoints used here are documented.
"""

import json
import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

from ...common.log_redaction import redact_url
from ...schemas.federation_schema import AnypointOrgConfig
from .base_client import BaseFederationClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)

logger = logging.getLogger(__name__)

ANYPOINT_SOURCE: str = "anypoint"
ANYPOINT_ATTRIBUTION: str = "MuleSoft Anypoint Exchange"

# Platform API paths, relative to the configured control-plane base_url.
TOKEN_PATH: str = "/accounts/api/v2/oauth2/token"
ASSETS_PATH: str = "/exchange/api/v2/assets"

# API Manager. The list response groups by Exchange asset and nests apis[], but
# omits endpoint detail; the per-instance call is what carries endpoint.uri.
APIMANAGER_APIS_PATH: str = "/apimanager/api/v1/organizations/{org_id}/environments/{env_id}/apis"
APIMANAGER_API_PATH: str = (
    "/apimanager/api/v1/organizations/{org_id}/environments/{env_id}/apis/{api_id}"
)

# An API Manager instance whose status is not this is configured but not
# necessarily listening. Importing one produces a server that fails health checks.
ACTIVE_INSTANCE_STATUS: str = "active"

# Token lifetime is 3600s in practice; refresh early so a long sync cannot
# straddle an expiry. Mirrors the 60s buffer in FederationAuthManager.
TOKEN_REFRESH_BUFFER_SECONDS: int = 60
DEFAULT_TOKEN_LIFETIME_SECONDS: int = 3600

# Exchange caps a single page; page until fewer than this many are returned.
ASSET_PAGE_SIZE: int = 50
MAX_ASSET_PAGES: int = 40

# Classifier names Exchange uses for the metadata file on each asset type.
MCP_METADATA_CLASSIFIER: str = "mcp-metadata"
AGENT_METADATA_CLASSIFIER: str = "agent-metadata"


def _safe_parse_json(
    raw: str | bytes | None,
    context: str,
) -> dict[str, Any]:
    """Parse JSON, returning an empty dict rather than raising.

    One malformed asset must not fail a whole sync batch.

    Args:
        raw: Raw JSON text
        context: Description used in the warning log

    Returns:
        Parsed dict, or empty dict if parsing fails
    """
    if not raw:
        return {}

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning(f"Failed to parse JSON for {context}: {e}")
        return {}

    if not isinstance(parsed, dict):
        logger.warning(f"Expected a JSON object for {context}, got {type(parsed).__name__}")
        return {}

    return parsed


def _sanitize_path_segment(value: str) -> str:
    """Reduce an asset id to a URL-safe path segment.

    Args:
        value: Raw Exchange assetId, or an API Manager instance label

    Returns:
        Lowercased segment containing only alphanumerics and hyphens
    """
    allowed = []
    for char in value.lower():
        if char.isalnum():
            allowed.append(char)
        # Whitespace becomes a separator, not nothing: instance labels are
        # human-written ("Orders MCP Server"), and dropping spaces outright
        # would run words together into "ordersmcpserver".
        elif char in {"-", "_", ".", " ", "\t"}:
            allowed.append("-")

    segment = "".join(allowed).strip("-")
    while "--" in segment:
        segment = segment.replace("--", "-")

    return segment


def _extract_transport(mcp_metadata: dict[str, Any]) -> tuple[str, str | None]:
    """Extract transport kind and path from an mcp-metadata document.

    Args:
        mcp_metadata: Parsed mcp-metadata JSON

    Returns:
        Tuple of (transport_type, path). Path is None when absent.
    """
    transport = mcp_metadata.get("transport") or {}
    if not isinstance(transport, dict):
        return "streamable-http", None

    # Exchange uses camelCase kinds ("streamableHttp"); ours are hyphenated.
    kind_map = {
        "streamablehttp": "streamable-http",
        "streamable-http": "streamable-http",
        "sse": "sse",
        "stdio": "stdio",
    }
    raw_kind = str(transport.get("kind", "streamableHttp")).lower()
    transport_type = kind_map.get(raw_kind, "streamable-http")

    path = transport.get("path")
    return transport_type, path if isinstance(path, str) else None


def _extract_attribute_url(asset: dict[str, Any]) -> str | None:
    """Read an absolute endpoint from the asset's ``attributes`` list.

    ``attributes`` is a list of ``{"key": ..., "value": ...}`` pairs. Assets
    imported by a scanner that knew the deployed endpoint carry a ``url``
    attribute holding a COMPLETE url, host included - e.g.
    ``https://mapstools.googleapis.com/mcp``. This is the authoritative
    endpoint when present, and it is more specific than anything derivable
    from ``mcp-metadata.transport`` (which holds a path only).

    Args:
        asset: Raw Exchange asset dict

    Returns:
        Absolute http(s) url, or None when the attribute is absent
    """
    attributes = asset.get("attributes")
    if not isinstance(attributes, list):
        return None

    for entry in attributes:
        if not isinstance(entry, dict) or entry.get("key") != "url":
            continue

        value = entry.get("value")
        if not isinstance(value, str):
            continue

        value = value.strip()
        # Only absolute http(s) urls are usable as a proxy target. A relative
        # value would silently become a bad route, so reject rather than guess.
        if value.startswith(("http://", "https://")):
            return value

    return None


def _extract_instance_url(instance: dict[str, Any]) -> str | None:
    """Read the backend endpoint from an API Manager instance detail response.

    ``endpoint.uri`` is the real upstream (e.g.
    ``https://orders-mcp-v4-kau0jd.wfsahu.usa-e1.cloudhub.io``).

    ``endpoint.proxyUri`` is deliberately NOT used: it is the Flex Gateway's own
    listener address, observed as ``http://0.0.0.0:8081/orders-mcp``. A wildcard
    bind address is not routable from here, and treating it as a proxy target
    would register an unreachable server.

    Args:
        instance: API Manager per-instance detail response

    Returns:
        Absolute http(s) url, or None when absent or unusable
    """
    endpoint = instance.get("endpoint")
    if not isinstance(endpoint, dict):
        return None

    uri = endpoint.get("uri")
    if not isinstance(uri, str):
        return None

    uri = uri.strip()
    if uri.startswith(("http://", "https://")):
        return uri

    return None


def _instance_path_suffix(instance: dict[str, Any]) -> str:
    """Build a stable, unique path suffix for one API Manager instance.

    Prefers the human-readable ``instanceLabel`` because it survives a
    redeployment; falls back to the numeric ``id``, which is unique but opaque.

    Args:
        instance: API Manager instance detail

    Returns:
        Sanitized path segment, never empty
    """
    label = instance.get("instanceLabel")
    if isinstance(label, str) and label.strip():
        suffix = _sanitize_path_segment(label)
        if suffix:
            return suffix

    return _sanitize_path_segment(str(instance.get("id", "instance")))


def _instance_provenance(instance: dict[str, Any] | None) -> dict[str, Any]:
    """Record which API Manager instance an imported record came from.

    Without this an operator cannot tell three records sharing one Exchange
    asset apart, nor find the instance again in API Manager.

    Args:
        instance: API Manager instance detail, or None

    Returns:
        Metadata fragment; empty when there is no instance
    """
    if not instance:
        return {"anypoint_api_instance_id": None, "anypoint_environment_id": None}

    endpoint = instance.get("endpoint")
    endpoint = endpoint if isinstance(endpoint, dict) else {}

    return {
        "anypoint_api_instance_id": instance.get("id"),
        "anypoint_instance_label": instance.get("instanceLabel"),
        "anypoint_environment_id": instance.get("environmentId"),
        "anypoint_instance_status": instance.get("status"),
        "anypoint_instance_stage": instance.get("stage"),
        "anypoint_technology": instance.get("technology"),
        "anypoint_endpoint_type": endpoint.get("type"),
        # The Flex Gateway listener, recorded but never used as a proxy target
        # because it is a wildcard bind address (0.0.0.0) in practice.
        "anypoint_proxy_uri": endpoint.get("proxyUri"),
    }


def _resolve_proxy_url(
    asset: dict[str, Any],
    path: str | None,
    instance: dict[str, Any] | None,
) -> str | None:
    """Determine the endpoint for an imported asset.

    Resolution order, most to least specific:

    1. The API Manager instance's ``endpoint.uri``, when an instance was
       resolved. This is the deployed endpoint for THIS instance, and it is the
       only source that distinguishes one instance of a multiply-deployed asset
       from another.
    2. The Exchange asset's own ``url`` attribute, when present. Asset-level, so
       it cannot distinguish between instances - correct only when there is one.
    3. None. The asset is discovery-only, which must not be papered over with a
       guessed or wildcard host.

    Note ``path`` (from ``mcp-metadata.transport``) is intentionally NOT joined
    onto either url. Both sources supply a complete endpoint, and the observed
    instance uris already include their own path where one applies. Appending
    would corrupt them.

    Args:
        asset: Raw Exchange asset dict
        path: Transport path from mcp-metadata; retained for provenance only
        instance: API Manager instance detail, when one was resolved

    Returns:
        Absolute URL, or None when no host is available
    """
    if instance:
        instance_url = _extract_instance_url(instance)
        if instance_url:
            return instance_url

    return _extract_attribute_url(asset)


class AnypointFederationClient(BaseFederationClient):
    """Client for fetching MCP and A2A assets from Anypoint Exchange."""

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 30,
        retry_attempts: int = 3,
    ):
        """
        Initialize the Anypoint federation client.

        Args:
            base_url: Anypoint control plane base URL
            timeout_seconds: HTTP request timeout
            retry_attempts: Number of retry attempts for failed requests
        """
        super().__init__(base_url, timeout_seconds, retry_attempts)
        self._access_token: str | None = None
        self._token_expiry: datetime | None = None

    def _get_access_token(
        self,
        org: AnypointOrgConfig,
    ) -> str | None:
        """Mint or reuse a Platform client-credentials token.

        Credentials are read from the environment by variable NAME, so they are
        never persisted in federation config.

        Args:
            org: Organization config naming the credential env vars

        Returns:
            Access token, or None if credentials are absent or the mint fails
        """
        if self._access_token and self._token_expiry:
            if datetime.now(UTC) < self._token_expiry:
                logger.debug("Reusing cached Anypoint access token")
                return self._access_token

        if not org.client_id_env_var or not org.client_secret_env_var:
            logger.error(
                f"Anypoint org '{org.org_id}' is missing client_id_env_var/"
                f"client_secret_env_var; cannot authenticate"
            )
            return None

        client_id = os.getenv(org.client_id_env_var)
        client_secret = os.getenv(org.client_secret_env_var)

        if not client_id or not client_secret:
            logger.error(
                f"Anypoint credentials not found in environment "
                f"({org.client_id_env_var}/{org.client_secret_env_var} unset or empty)"
            )
            return None

        token_url = f"{self.endpoint}{TOKEN_PATH}"
        logger.info(f"Minting Anypoint access token for org {org.org_id}")

        response = self._make_request(
            url=token_url,
            method="POST",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )

        if not response:
            logger.error("Anypoint token request failed")
            return None

        token = response.get("access_token")
        if not token:
            logger.error("Anypoint token response contained no access_token")
            return None

        expires_in = response.get("expires_in", DEFAULT_TOKEN_LIFETIME_SECONDS)
        try:
            lifetime = int(expires_in)
        except (TypeError, ValueError):
            lifetime = DEFAULT_TOKEN_LIFETIME_SECONDS

        self._access_token = token
        self._token_expiry = datetime.now(UTC) + timedelta(
            seconds=max(lifetime - TOKEN_REFRESH_BUFFER_SECONDS, 0)
        )
        logger.info(f"Anypoint token acquired (expires in {lifetime}s)")

        return self._access_token

    def _fetch_asset_page(
        self,
        org_id: str,
        token: str,
        offset: int,
    ) -> list[dict[str, Any]]:
        """Fetch one page of assets for an organization.

        Args:
            org_id: Anypoint organizationId
            token: Platform access token
            offset: Pagination offset

        Returns:
            List of raw asset dicts, empty on failure
        """
        response = self._make_request(
            url=f"{self.endpoint}{ASSETS_PATH}",
            headers={"Authorization": f"Bearer {token}"},
            params={
                "organizationId": org_id,
                "limit": ASSET_PAGE_SIZE,
                "offset": offset,
            },
        )

        # The listing endpoint returns a bare JSON array, not an envelope.
        if isinstance(response, list):
            return response

        if isinstance(response, dict):
            assets = response.get("assets")
            if isinstance(assets, list):
                return assets

        return []

    def fetch_assets(
        self,
        org: AnypointOrgConfig,
    ) -> list[dict[str, Any]]:
        """Fetch all assets of the configured types for one organization.

        Args:
            org: Organization config

        Returns:
            List of raw asset dicts matching the configured asset types
        """
        token = self._get_access_token(org)
        if not token:
            return []

        wanted = set(org.asset_types)
        collected: list[dict[str, Any]] = []
        offset = 0

        for page in range(MAX_ASSET_PAGES):
            assets = self._fetch_asset_page(org.org_id, token, offset)
            if not assets:
                break

            for asset in assets:
                if not isinstance(asset, dict):
                    continue
                if asset.get("type") in wanted:
                    collected.append(asset)

            if len(assets) < ASSET_PAGE_SIZE:
                break

            offset += ASSET_PAGE_SIZE

            if page == MAX_ASSET_PAGES - 1:
                logger.warning(
                    f"Anypoint asset listing for org {org.org_id} hit the "
                    f"{MAX_ASSET_PAGES}-page cap; results may be truncated"
                )

        logger.info(
            f"Fetched {len(collected)} assets of types {sorted(wanted)} "
            f"from Anypoint org {org.org_id}"
        )
        return collected

    def fetch_api_instances(
        self,
        org: AnypointOrgConfig,
    ) -> dict[tuple[str, str], list[dict[str, Any]]]:
        """Fetch API Manager instances for one environment, indexed by asset.

        This is the second half of the two-service join. Exchange holds the
        descriptor; API Manager holds the deployed instance and its endpoint.
        They join on (assetId, assetVersion), which an API instance carries
        verbatim from Exchange.

        The list response groups by asset and nests ``apis[]``, but omits
        endpoint detail, so each instance needs a follow-up detail call.

        Returns an empty index when no ``environment_id`` is configured -
        imports then fall back to asset-level urls and are usually
        discovery-only. That is deliberate: guessing an environment would risk
        importing a sandbox endpoint as if it were production.

        Args:
            org: Organization config, including environment_id

        Returns:
            Mapping of (assetId, assetVersion) -> list of instance detail dicts
        """
        if not org.environment_id:
            logger.info(
                f"Anypoint org {org.org_id} has no environment_id; skipping API Manager "
                f"endpoint resolution (imports will be discovery-only unless the asset "
                f"carries its own url attribute)"
            )
            return {}

        token = self._get_access_token(org)
        if not token:
            return {}

        listing = self._make_request(
            url=self.endpoint
            + APIMANAGER_APIS_PATH.format(org_id=org.org_id, env_id=org.environment_id),
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": ASSET_PAGE_SIZE},
        )

        if not isinstance(listing, dict):
            logger.warning(
                f"Unexpected API Manager listing shape for org {org.org_id} "
                f"environment {org.environment_id}"
            )
            return {}

        index: dict[tuple[str, str], list[dict[str, Any]]] = {}
        grouped = listing.get("assets")
        if not isinstance(grouped, list):
            return {}

        for group in grouped:
            if not isinstance(group, dict):
                continue

            for api in group.get("apis") or []:
                if not isinstance(api, dict):
                    continue

                api_id = api.get("id")
                if api_id is None:
                    continue

                detail = self._fetch_api_instance(org, token, api_id)
                if not detail:
                    continue

                key = (
                    str(detail.get("assetId", group.get("assetId", ""))),
                    str(detail.get("assetVersion", "")),
                )
                index.setdefault(key, []).append(detail)

        total = sum(len(v) for v in index.values())
        logger.info(
            f"Resolved {total} API Manager instance(s) across {len(index)} asset "
            f"version(s) in environment {org.environment_id}"
        )
        return index

    def _fetch_api_instance(
        self,
        org: AnypointOrgConfig,
        token: str,
        api_id: Any,
    ) -> dict[str, Any] | None:
        """Fetch one API Manager instance's detail, which carries endpoint.uri.

        Args:
            org: Organization config
            token: Platform access token
            api_id: API Manager numeric instance id

        Returns:
            Instance detail dict, or None on failure
        """
        detail = self._make_request(
            url=self.endpoint
            + APIMANAGER_API_PATH.format(
                org_id=org.org_id, env_id=org.environment_id, api_id=api_id
            ),
            headers={"Authorization": f"Bearer {token}"},
        )

        if isinstance(detail, dict):
            return detail

        logger.warning(f"Could not fetch API Manager instance {api_id}")
        return None

    def fetch_asset_metadata(
        self,
        asset: dict[str, Any],
        classifier: str,
        org: AnypointOrgConfig,
    ) -> dict[str, Any]:
        """Fetch and parse an asset's attached metadata document.

        Metadata files are served from external links (S3 presigned URLs), so
        this is a second hop per asset. The link is registrant-influenced, so
        it goes through the same SSRF-guarded transport as every other
        federation fetch and carries NO credential.

        Args:
            asset: Raw Exchange asset dict
            classifier: File classifier to look for (e.g. "mcp-metadata")
            org: Organization config, for logging context

        Returns:
            Parsed metadata dict, empty if absent or unparseable
        """
        files = asset.get("files")
        if not isinstance(files, list):
            return {}

        for entry in files:
            if not isinstance(entry, dict):
                continue
            if entry.get("classifier") != classifier:
                continue
            if entry.get("packaging") not in (None, "json", "raw"):
                continue

            link = entry.get("externalLink")
            if not isinstance(link, str) or not link:
                continue

            logger.debug(
                f"Fetching {classifier} for asset {asset.get('assetId')} from {redact_url(link)}"
            )
            # No Authorization header: the link is presigned and the target is
            # registrant-influenced, so a credential must never be attached.
            payload = self._make_request(url=link)
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, str):
                return _safe_parse_json(payload, context=f"{classifier} for {asset.get('assetId')}")

        logger.debug(f"Asset {asset.get('assetId')} in org {org.org_id} has no {classifier} file")
        return {}

    def transform_mcp_asset(
        self,
        asset: dict[str, Any],
        org: AnypointOrgConfig,
        instance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Transform an Exchange ``mcp`` asset into server registration data.

        One asset can have several API Manager instances, so this is called once
        per instance and the resulting path is instance-qualified. Called with
        ``instance=None`` for an asset that has no deployed instance, which
        yields a discovery-only record.

        Args:
            asset: Raw Exchange asset dict
            org: Organization config
            instance: API Manager instance detail, when one was resolved

        Returns:
            Server data dict suitable for registration
        """
        asset_id = str(asset.get("assetId", ""))
        group_id = str(asset.get("groupId", ""))
        version = str(asset.get("version", "1.0.0"))
        name = asset.get("name") or asset_id

        metadata = self.fetch_asset_metadata(asset, MCP_METADATA_CLASSIFIER, org)
        transport_type, path = _extract_transport(metadata)
        proxy_url = _resolve_proxy_url(asset, path, instance)

        tools = metadata.get("tools")
        tool_list = tools if isinstance(tools, list) else []

        # Several instances of one asset must not collide on a single path, so the
        # instance label (or id) qualifies it. Without an instance the asset id
        # alone is unambiguous.
        path_segment = _sanitize_path_segment(asset_id)
        if instance:
            path_segment = f"{path_segment}-{_instance_path_suffix(instance)}"
            # An instance label is more specific than the asset name when one
            # asset is deployed several times ("Salesforce SObject Reads" vs
            # the generic "Omni Gateway Orders MCP Server").
            label = instance.get("instanceLabel")
            if isinstance(label, str) and label.strip():
                name = label.strip()

        return {
            "source": ANYPOINT_SOURCE,
            "server_name": name,
            "description": asset.get("description") or f"Anypoint Exchange MCP server: {name}",
            "version": version,
            "title": name,
            "proxy_pass_url": proxy_url,
            "transport_type": transport_type,
            "requires_auth": False,
            "auth_headers": [],
            "tags": [
                "anypoint",
                "mulesoft",
                "federated",
                "mcp",
                f"org-{_sanitize_path_segment(org.org_id)[:12]}",
            ],
            "tool_list": tool_list,
            "num_tools": len(tool_list),
            "metadata": {
                "anypoint_group_id": group_id,
                "anypoint_asset_id": asset_id,
                "anypoint_version": version,
                "anypoint_org_id": org.org_id,
                "asset_type": "mcp",
                "transport_path": path,
                "protocol_version": metadata.get("protocolVersion"),
                "capabilities": metadata.get("capabilities"),
                # Recorded explicitly so an operator can tell a discovery-only
                # import from a connectable one without inspecting proxy_pass_url.
                "discovery_only": proxy_url is None,
                **_instance_provenance(instance),
            },
            "cached_at": datetime.now(UTC).isoformat(),
            "is_read_only": True,
            "attribution_label": ANYPOINT_ATTRIBUTION,
            "path": f"/anypoint-{path_segment}",
            "is_enabled": False,
            "health_status": "unknown",
        }

    def transform_a2a_asset(
        self,
        asset: dict[str, Any],
        org: AnypointOrgConfig,
        instance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Transform an Exchange ``a2a`` or ``agent`` asset into agent data.

        The Exchange asset itself carries provenance only - no url,
        securitySchemes, or skills. An API Manager instance supplies the
        endpoint when one exists, so the record is sparse but can still be
        connectable.

        Args:
            asset: Raw Exchange asset dict
            org: Organization config
            instance: API Manager instance detail, when one was resolved

        Returns:
            Agent data dict suitable for registration
        """
        asset_id = str(asset.get("assetId", ""))
        group_id = str(asset.get("groupId", ""))
        version = str(asset.get("version", "1.0.0"))
        name = asset.get("name") or asset_id

        metadata = self.fetch_asset_metadata(asset, AGENT_METADATA_CLASSIFIER, org)
        provenance = metadata.get("provenance")

        agent_url = _resolve_proxy_url(asset, None, instance) or ""

        path_segment = _sanitize_path_segment(asset_id)
        if instance:
            path_segment = f"{path_segment}-{_instance_path_suffix(instance)}"
            label = instance.get("instanceLabel")
            if isinstance(label, str) and label.strip():
                name = label.strip()

        return {
            "source": ANYPOINT_SOURCE,
            "name": name,
            "description": asset.get("description") or f"Anypoint Exchange agent: {name}",
            "url": agent_url,
            "path": f"/agents/anypoint-{path_segment}",
            "version": version,
            "supported_protocol": "a2a" if asset.get("type") == "a2a" else "other",
            "skills": [],
            "tags": [
                "anypoint",
                "mulesoft",
                "federated",
                str(asset.get("type", "agent")),
                f"org-{_sanitize_path_segment(org.org_id)[:12]}",
            ],
            "is_enabled": False,
            "is_read_only": True,
            "attribution_label": ANYPOINT_ATTRIBUTION,
            "metadata": {
                "anypoint_group_id": group_id,
                "anypoint_asset_id": asset_id,
                "anypoint_version": version,
                "anypoint_org_id": org.org_id,
                "asset_type": asset.get("type"),
                "provenance": provenance,
                "discovery_only": not agent_url,
                **_instance_provenance(instance),
            },
            "cached_at": datetime.now(UTC).isoformat(),
        }

    def iter_asset_instances(
        self,
        asset: dict[str, Any],
        instance_index: dict[tuple[str, str], list[dict[str, Any]]],
    ) -> list[dict[str, Any] | None]:
        """Return the API Manager instances for one asset, or [None] if it has none.

        This is what turns the one-to-many relationship into a list the caller can
        loop over uniformly: an asset with three instances yields three entries, and
        an asset with none yields a single ``None`` so it still imports as a
        discovery-only record rather than being dropped.

        The join is on (assetId, assetVersion), which an API instance carries
        verbatim from Exchange.

        Args:
            asset: Raw Exchange asset dict
            instance_index: Output of fetch_api_instances()

        Returns:
            List of instance dicts, or ``[None]`` when the asset has no instances
        """
        key = (str(asset.get("assetId", "")), str(asset.get("version", "")))
        instances = instance_index.get(key)

        if not instances:
            return [None]

        return list(instances)

    def fetch_server(self, server_name: str, **kwargs) -> dict[str, Any] | None:
        """Not supported: Exchange is enumerated, not queried by server name.

        Implemented to satisfy BaseFederationClient. Use fetch_assets instead.

        Args:
            server_name: Unused
            **kwargs: Unused

        Returns:
            None
        """
        logger.warning(
            "AnypointFederationClient.fetch_server is not supported; "
            "use fetch_assets to enumerate an organization"
        )
        return None

    def fetch_all_servers(self, server_names: list[str], **kwargs) -> list[dict[str, Any]]:
        """Not supported: Exchange is enumerated, not queried by server name.

        Implemented to satisfy BaseFederationClient. Use fetch_assets instead.

        Args:
            server_names: Unused
            **kwargs: Unused

        Returns:
            Empty list
        """
        logger.warning(
            "AnypointFederationClient.fetch_all_servers is not supported; "
            "use fetch_assets to enumerate an organization"
        )
        return []

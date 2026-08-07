"""Tests for the Anypoint Exchange federation client.

Payload shapes in these fixtures were captured from a live Anypoint
organization, not invented:

- An ``mcp`` asset's ``mcp-metadata`` carries tools with JSON Schemas plus a
  transport holding a path and no host.
- The complete endpoint, when one exists, lives in the asset's ``attributes``
  list under the ``url`` key - not in the transport descriptor. 2 of 3 ``mcp``
  assets in the sample org had one; no ``a2a`` asset did.
- ``a2a`` and ``agent`` assets carry provenance only.
"""

import json
from unittest.mock import patch

import pytest

from registry.schemas.federation_schema import (
    AnypointFederationConfig,
    AnypointOrgConfig,
)
from registry.services.federation.anypoint_client import (
    AnypointFederationClient,
    _extract_attribute_url,
    _extract_instance_url,
    _extract_transport,
    _instance_path_suffix,
    _instance_provenance,
    _resolve_proxy_url,
    _safe_parse_json,
    _sanitize_path_segment,
)

ORG_ID = "2ba26956-d5d9-4a43-8839-37c88b542c7d"
ENV_ID = "b6202d2b-1753-4f0f-9172-e8556a3c79d2"

# Captured live from API Manager instance 20943747 (Production environment).
# status is forced to "active" here; the live instances report "inactive", which
# is covered separately by the import-gate tests.
APIM_INSTANCE = {
    "id": 20943747,
    "groupId": ORG_ID,
    "assetId": "omni-gateway-orders-mcp-spec",
    "assetVersion": "1.0.1",
    "productVersion": "v1.0",
    "environmentId": ENV_ID,
    "instanceLabel": "Orders MCP Server",
    "autodiscoveryInstanceName": "v1.0:20943747",
    "technology": "flexGateway",
    "stage": "release",
    "status": "active",
    "endpoint": {
        "id": 5377837,
        "type": "mcp",
        "uri": "https://orders-mcp-v4-kau0jd.wfsahu.usa-e1.cloudhub.io",
        "proxyUri": "http://0.0.0.0:8081/orders-mcp",
        "apiGatewayVersion": "1.13.1",
        "deploymentType": "HY",
    },
}

MCP_METADATA = {
    "tools": [
        {
            "name": "listOrders",
            "description": "List all customer orders with optional filters",
            "inputSchema": {
                "type": "object",
                "properties": {"customerId": {"type": "string"}},
            },
        },
        {"name": "getOrder", "inputSchema": {"required": ["orderId"]}},
        {"name": "createOrder"},
    ],
    "resources": [],
    "capabilities": {"tools": {"listChanged": False}},
    "transport": {"kind": "streamableHttp", "path": "/mcp"},
    "protocolVersion": "2025-03-26",
    "platform": "mulesoft",
}

AGENT_METADATA = {
    "provenance": {
        "salesforce": {
            "botDefinitionId": "employee-a2a-aws-test",
            "platform": "Agentforce",
            "status": "Active",
        }
    }
}

MCP_ASSET = {
    "groupId": ORG_ID,
    "assetId": "omni-gateway-orders-mcp-server",
    "version": "1.0.0",
    "name": "Omni Gateway Orders MCP Server",
    "type": "mcp",
    "status": "published",
    "files": [
        {
            "classifier": "mcp-metadata",
            "packaging": "json",
            "externalLink": "https://exchange2-asset-manager.s3.amazonaws.com/mcp-metadata.json",
        }
    ],
}

MCP_ASSET_WITH_URL = {
    **MCP_ASSET,
    "assetId": "google-maps-mcp",
    "name": "Google Maps MCP",
    # Captured live: 2 of 3 mcp assets in the sample org carry this.
    "attributes": [
        {"key": "platform", "value": "Google"},
        {"key": "url", "value": "https://mapstools.googleapis.com/mcp"},
    ],
}

A2A_ASSET = {
    "groupId": ORG_ID,
    "assetId": "employee-a-2-a-aws-test",
    "version": "1.0.0",
    "name": "employee a2a aws test",
    "type": "a2a",
    "status": "published",
    "files": [
        {
            "classifier": "agent-metadata",
            "packaging": "json",
            "externalLink": "https://exchange2-asset-manager.s3.amazonaws.com/agent-metadata.json",
        }
    ],
}


def _org(**overrides) -> AnypointOrgConfig:
    """Build an org config with credential env vars set."""
    defaults = {
        "org_id": ORG_ID,
        "client_id_env_var": "ANYPOINT_CLIENT_ID",
        "client_secret_env_var": "ANYPOINT_CLIENT_SECRET",
    }
    defaults.update(overrides)
    return AnypointOrgConfig(**defaults)


@pytest.fixture
def client() -> AnypointFederationClient:
    """Client pointed at the public control plane."""
    return AnypointFederationClient(base_url="https://anypoint.mulesoft.com")


class TestHelpers:
    """Tests for the module-level helper functions."""

    def test_safe_parse_json_returns_dict(self):
        assert _safe_parse_json(json.dumps({"a": 1}), context="test") == {"a": 1}

    @pytest.mark.parametrize(
        "raw",
        ["not json", "", None, "[1, 2, 3]", '"a string"'],
        ids=["malformed", "empty", "none", "array", "scalar"],
    )
    def test_safe_parse_json_never_raises(self, raw):
        """One bad asset must not abort a batch."""
        assert _safe_parse_json(raw, context="test") == {}

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Omni_Gateway.Orders", "omni-gateway-orders"),
            ("UPPER", "upper"),
            ("a//b", "ab"),
            ("--leading--trailing--", "leading-trailing"),
            ("a___b", "a-b"),
        ],
    )
    def test_sanitize_path_segment(self, raw, expected):
        assert _sanitize_path_segment(raw) == expected

    def test_sanitize_path_segment_strips_traversal(self):
        """Path separators and dots must not survive into a registry path."""
        result = _sanitize_path_segment("../../etc/passwd")
        assert "/" not in result
        assert ".." not in result

    def test_extract_transport_maps_camelcase_kind(self):
        """Exchange says streamableHttp; our records say streamable-http."""
        transport_type, path = _extract_transport(MCP_METADATA)
        assert transport_type == "streamable-http"
        assert path == "/mcp"

    def test_extract_transport_defaults_when_absent(self):
        transport_type, path = _extract_transport({})
        assert transport_type == "streamable-http"
        assert path is None

    def test_extract_transport_tolerates_non_dict(self):
        transport_type, path = _extract_transport({"transport": "streamableHttp"})
        assert transport_type == "streamable-http"
        assert path is None


class TestExtractAttributeUrl:
    """The endpoint lives in attributes[], not in the transport descriptor."""

    def test_reads_absolute_url(self):
        """Captured live: google-maps-mcp carries a complete endpoint."""
        asset = {
            "attributes": [
                {"key": "platform", "value": "Google"},
                {"key": "url", "value": "https://mapstools.googleapis.com/mcp"},
            ]
        }
        assert _extract_attribute_url(asset) == "https://mapstools.googleapis.com/mcp"

    def test_absent_url_key_returns_none(self):
        """Captured live: omni-gateway-orders-mcp-spec has platform only."""
        asset = {"attributes": [{"key": "platform", "value": "mulesoft"}]}
        assert _extract_attribute_url(asset) is None

    def test_no_attributes_returns_none(self):
        assert _extract_attribute_url({"assetId": "x"}) is None

    @pytest.mark.parametrize(
        "attributes",
        ["not-a-list", None, [{"key": "url"}], [{"key": "url", "value": 42}], ["garbage"]],
        ids=["string", "none", "no-value", "non-string-value", "non-dict-entry"],
    )
    def test_malformed_attributes_return_none(self, attributes):
        """A malformed attributes list must not raise."""
        assert _extract_attribute_url({"attributes": attributes}) is None

    @pytest.mark.parametrize(
        "value",
        ["/mcp", "mapstools.googleapis.com/mcp", "ftp://host/mcp", "  ", "javascript:alert(1)"],
        ids=["relative", "schemeless", "wrong-scheme", "blank", "javascript"],
    )
    def test_rejects_non_http_urls(self, value):
        """A relative or non-http value would become a bad proxy target."""
        asset = {"attributes": [{"key": "url", "value": value}]}
        assert _extract_attribute_url(asset) is None


class TestExtractInstanceUrl:
    """endpoint.uri is the backend; proxyUri is the gateway's own listener."""

    def test_reads_endpoint_uri(self):
        """Captured live from API Manager instance 20943747."""
        assert (
            _extract_instance_url(APIM_INSTANCE)
            == "https://orders-mcp-v4-kau0jd.wfsahu.usa-e1.cloudhub.io"
        )

    def test_never_returns_proxy_uri(self):
        """proxyUri is http://0.0.0.0:8081/... - a wildcard bind, not routable."""
        instance = {"endpoint": {"proxyUri": "http://0.0.0.0:8081/orders-mcp"}}
        assert _extract_instance_url(instance) is None

    @pytest.mark.parametrize(
        "endpoint",
        [None, "not-a-dict", {}, {"uri": None}, {"uri": 42}, {"uri": "/relative"}],
        ids=["none", "string", "empty", "null-uri", "non-string", "relative"],
    )
    def test_malformed_endpoint_returns_none(self, endpoint):
        assert _extract_instance_url({"endpoint": endpoint}) is None


class TestResolveProxyUrl:
    """Endpoint resolution: API Manager instance, then asset attribute, else none."""

    def test_instance_url_wins_over_attribute(self):
        """The instance endpoint is per-deployment; the attribute is per-asset."""
        asset = {"attributes": [{"key": "url", "value": "https://asset-level.example.com/mcp"}]}
        assert (
            _resolve_proxy_url(asset, "/mcp", APIM_INSTANCE)
            == "https://orders-mcp-v4-kau0jd.wfsahu.usa-e1.cloudhub.io"
        )

    def test_falls_back_to_attribute_when_no_instance(self):
        asset = {"attributes": [{"key": "url", "value": "https://mapstools.googleapis.com/mcp"}]}
        assert _resolve_proxy_url(asset, "/mcp", None) == "https://mapstools.googleapis.com/mcp"

    def test_falls_back_to_attribute_when_instance_has_no_uri(self):
        """An instance without a usable uri must not mask the asset-level url."""
        asset = {"attributes": [{"key": "url", "value": "https://mapstools.googleapis.com/mcp"}]}
        instance = {"id": 1, "endpoint": {"proxyUri": "http://0.0.0.0:8081/x"}}
        assert _resolve_proxy_url(asset, "/mcp", instance) == "https://mapstools.googleapis.com/mcp"

    def test_returns_none_with_neither(self):
        """No instance and no attribute url means discovery-only."""
        assert _resolve_proxy_url({}, "/mcp", None) is None

    def test_never_appends_transport_path(self):
        """Both sources give complete urls; appending the path would corrupt them."""
        result = _resolve_proxy_url({}, "/mcp", APIM_INSTANCE)
        assert result == "https://orders-mcp-v4-kau0jd.wfsahu.usa-e1.cloudhub.io"
        assert not result.endswith("/mcp/mcp")


class TestInstancePathSuffix:
    """Several instances of one asset must not collide on a path."""

    def test_prefers_label(self):
        assert _instance_path_suffix(APIM_INSTANCE) == "orders-mcp-server"

    def test_falls_back_to_id(self):
        assert _instance_path_suffix({"id": 20943747}) == "20943747"

    @pytest.mark.parametrize(
        "label", [None, "", "   ", 42], ids=["none", "empty", "blank", "non-string"]
    )
    def test_unusable_label_falls_back_to_id(self, label):
        assert _instance_path_suffix({"id": 99, "instanceLabel": label}) == "99"

    def test_three_instances_of_one_asset_get_distinct_suffixes(self):
        """The live case: one asset, three instances, three labels."""
        labels = ["Orders MCP Server", "Salesforce SObject Reads", "Salesforce SObject All"]
        suffixes = [
            _instance_path_suffix({"id": i, "instanceLabel": s}) for i, s in enumerate(labels)
        ]
        assert len(set(suffixes)) == 3


class TestInstanceProvenance:
    """An operator must be able to find the source instance again."""

    def test_records_instance_identity(self):
        p = _instance_provenance(APIM_INSTANCE)
        assert p["anypoint_api_instance_id"] == 20943747
        assert p["anypoint_instance_label"] == "Orders MCP Server"
        assert p["anypoint_environment_id"] == ENV_ID
        assert p["anypoint_instance_status"] == "active"
        assert p["anypoint_endpoint_type"] == "mcp"

    def test_records_proxy_uri_without_using_it(self):
        """proxyUri is kept for diagnosis but must never be the proxy target."""
        p = _instance_provenance(APIM_INSTANCE)
        assert p["anypoint_proxy_uri"] == "http://0.0.0.0:8081/orders-mcp"

    def test_none_instance_yields_null_fields(self):
        p = _instance_provenance(None)
        assert p["anypoint_api_instance_id"] is None
        assert p["anypoint_environment_id"] is None


class TestIterAssetInstances:
    """The one-to-many join, and the must-not-drop-assets rule."""

    def test_returns_all_instances_for_an_asset(self, client):
        index = {(MCP_ASSET["assetId"], MCP_ASSET["version"]): [{"id": 1}, {"id": 2}, {"id": 3}]}
        assert len(client.iter_asset_instances(MCP_ASSET, index)) == 3

    def test_asset_with_no_instances_yields_one_none(self, client):
        """It must still import as discovery-only, not be dropped."""
        assert client.iter_asset_instances(MCP_ASSET, {}) == [None]

    def test_join_is_on_asset_id_and_version(self, client):
        """A version mismatch must not join."""
        index = {(MCP_ASSET["assetId"], "9.9.9"): [{"id": 1}]}
        assert client.iter_asset_instances(MCP_ASSET, index) == [None]


class TestAccessToken:
    """Token minting reads credentials by env-var name, never from config."""

    def test_missing_env_var_names_returns_none(self, client):
        """Fail closed when the config names no credential vars."""
        org = AnypointOrgConfig(org_id=ORG_ID)
        with patch.object(client, "_make_request") as mock_request:
            assert client._get_access_token(org) is None
            mock_request.assert_not_called()

    def test_unset_env_vars_returns_none(self, client, monkeypatch):
        """Named vars that are absent from the environment fail closed."""
        monkeypatch.delenv("ANYPOINT_CLIENT_ID", raising=False)
        monkeypatch.delenv("ANYPOINT_CLIENT_SECRET", raising=False)
        with patch.object(client, "_make_request") as mock_request:
            assert client._get_access_token(_org()) is None
            mock_request.assert_not_called()

    def test_empty_env_var_returns_none(self, client, monkeypatch):
        """An empty credential is as bad as a missing one."""
        monkeypatch.setenv("ANYPOINT_CLIENT_ID", "")
        monkeypatch.setenv("ANYPOINT_CLIENT_SECRET", "secret")
        with patch.object(client, "_make_request") as mock_request:
            assert client._get_access_token(_org()) is None
            mock_request.assert_not_called()

    def test_mints_and_caches_token(self, client, monkeypatch):
        monkeypatch.setenv("ANYPOINT_CLIENT_ID", "id-value")
        monkeypatch.setenv("ANYPOINT_CLIENT_SECRET", "secret-value")

        with patch.object(
            client,
            "_make_request",
            return_value={"access_token": "tok-abc", "expires_in": 3600},
        ) as mock_request:
            assert client._get_access_token(_org()) == "tok-abc"
            # Second call must reuse the cache rather than re-mint.
            assert client._get_access_token(_org()) == "tok-abc"
            assert mock_request.call_count == 1

    def test_token_request_posts_credentials_in_body(self, client, monkeypatch):
        """Secrets go in the body, never the URL or query string."""
        monkeypatch.setenv("ANYPOINT_CLIENT_ID", "id-value")
        monkeypatch.setenv("ANYPOINT_CLIENT_SECRET", "secret-value")

        with patch.object(
            client, "_make_request", return_value={"access_token": "t"}
        ) as mock_request:
            client._get_access_token(_org())

        kwargs = mock_request.call_args.kwargs
        assert kwargs["method"] == "POST"
        assert kwargs["data"]["grant_type"] == "client_credentials"
        assert kwargs["data"]["client_secret"] == "secret-value"
        assert "secret-value" not in kwargs["url"]

    def test_response_without_token_returns_none(self, client, monkeypatch):
        monkeypatch.setenv("ANYPOINT_CLIENT_ID", "id")
        monkeypatch.setenv("ANYPOINT_CLIENT_SECRET", "secret")
        with patch.object(client, "_make_request", return_value={"scope": "read"}):
            assert client._get_access_token(_org()) is None

    def test_non_numeric_expires_in_falls_back(self, client, monkeypatch):
        """A malformed expires_in must not raise."""
        monkeypatch.setenv("ANYPOINT_CLIENT_ID", "id")
        monkeypatch.setenv("ANYPOINT_CLIENT_SECRET", "secret")
        with patch.object(
            client,
            "_make_request",
            return_value={"access_token": "t", "expires_in": "soon"},
        ):
            assert client._get_access_token(_org()) == "t"


class TestFetchAssets:
    """Asset enumeration, filtering, and pagination."""

    def test_filters_to_configured_types(self, client, monkeypatch):
        monkeypatch.setenv("ANYPOINT_CLIENT_ID", "id")
        monkeypatch.setenv("ANYPOINT_CLIENT_SECRET", "secret")

        listing = [
            MCP_ASSET,
            A2A_ASSET,
            {"assetId": "generic", "type": "agent", "status": "published"},
            {"assetId": "an-api", "type": "rest-api", "status": "published"},
        ]

        with patch.object(client, "_get_access_token", return_value="tok"):
            with patch.object(client, "_fetch_asset_page", return_value=listing):
                assets = client.fetch_assets(_org())

        types = {a["type"] for a in assets}
        assert types == {"mcp", "a2a"}, "default asset_types must exclude agent and rest-api"

    def test_no_token_returns_empty(self, client):
        """Without a token, no request is attempted."""
        with patch.object(client, "_get_access_token", return_value=None):
            with patch.object(client, "_fetch_asset_page") as mock_page:
                assert client.fetch_assets(_org()) == []
                mock_page.assert_not_called()

    def test_stops_on_short_page(self, client):
        """A page smaller than the page size is the last page."""
        with patch.object(client, "_get_access_token", return_value="tok"):
            with patch.object(client, "_fetch_asset_page", return_value=[MCP_ASSET]) as mock_page:
                client.fetch_assets(_org())
                assert mock_page.call_count == 1

    def test_paginates_until_short_page(self, client):
        """A full page triggers another fetch."""
        full_page = [dict(MCP_ASSET, assetId=f"asset-{i}") for i in range(50)]
        pages = [full_page, [MCP_ASSET]]

        with patch.object(client, "_get_access_token", return_value="tok"):
            with patch.object(client, "_fetch_asset_page", side_effect=pages) as mock_page:
                assets = client.fetch_assets(_org())

        assert mock_page.call_count == 2
        assert len(assets) == 51
        # Offset must advance, or pagination would loop on page one forever.
        assert mock_page.call_args_list[1].args[2] == 50

    def test_skips_non_dict_entries(self, client):
        """A malformed listing entry must not raise."""
        with patch.object(client, "_get_access_token", return_value="tok"):
            with patch.object(
                client, "_fetch_asset_page", return_value=[MCP_ASSET, "garbage", None]
            ):
                assets = client.fetch_assets(_org())
        assert len(assets) == 1


class TestFetchAssetMetadata:
    """Metadata is a second hop to a presigned link."""

    def test_returns_parsed_metadata(self, client):
        with patch.object(client, "_make_request", return_value=MCP_METADATA):
            result = client.fetch_asset_metadata(MCP_ASSET, "mcp-metadata", _org())
        assert result["protocolVersion"] == "2025-03-26"

    def test_never_sends_credentials_to_external_link(self, client):
        """The link is registrant-influenced, so no token may be attached."""
        with patch.object(client, "_make_request", return_value={}) as mock_request:
            client.fetch_asset_metadata(MCP_ASSET, "mcp-metadata", _org())

        kwargs = mock_request.call_args.kwargs
        assert "headers" not in kwargs or not kwargs.get("headers")

    def test_missing_classifier_returns_empty(self, client):
        with patch.object(client, "_make_request") as mock_request:
            result = client.fetch_asset_metadata(MCP_ASSET, "nonexistent", _org())
            assert result == {}
            mock_request.assert_not_called()

    def test_no_files_returns_empty(self, client):
        assert client.fetch_asset_metadata({"assetId": "x"}, "mcp-metadata", _org()) == {}

    def test_files_not_a_list_returns_empty(self, client):
        asset = {"assetId": "x", "files": "not-a-list"}
        assert client.fetch_asset_metadata(asset, "mcp-metadata", _org()) == {}


class TestTransformMcpAsset:
    """The mcp type is where descriptor fidelity is high."""

    def test_carries_tools_and_protocol(self, client):
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET, _org())

        assert result["num_tools"] == 3
        assert result["tool_list"][0]["name"] == "listOrders"
        assert result["transport_type"] == "streamable-http"
        assert result["metadata"]["protocol_version"] == "2025-03-26"

    def test_discovery_only_when_no_attribute_url_or_override(self, client):
        """An asset with no url attribute and no override cannot be called."""
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET, _org())

        assert result["proxy_pass_url"] is None
        assert result["metadata"]["discovery_only"] is True

    def test_connectable_from_attribute_url_alone(self, client):
        """An asset carrying a url attribute needs no operator configuration."""
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET_WITH_URL, _org())

        assert result["proxy_pass_url"] == "https://mapstools.googleapis.com/mcp"
        assert result["metadata"]["discovery_only"] is False

    def test_connectable_from_api_manager_instance(self, client):
        """The live case: Exchange has no url, API Manager supplies it."""
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET, _org(), APIM_INSTANCE)

        assert result["proxy_pass_url"] == "https://orders-mcp-v4-kau0jd.wfsahu.usa-e1.cloudhub.io"
        assert result["metadata"]["discovery_only"] is False

    def test_instance_qualifies_the_path(self, client):
        """Three instances of one asset must land on three distinct paths."""
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            paths = {
                client.transform_mcp_asset(
                    MCP_ASSET, _org(), {**APIM_INSTANCE, "id": i, "instanceLabel": label}
                )["path"]
                for i, label in enumerate(
                    ["Orders MCP Server", "Salesforce SObject Reads", "Salesforce SObject All"]
                )
            }

        assert len(paths) == 3
        assert "/anypoint-omni-gateway-orders-mcp-server-orders-mcp-server" in paths

    def test_instance_label_becomes_the_name(self, client):
        """ "Salesforce SObject Reads" is more useful than the generic asset name."""
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(
                MCP_ASSET, _org(), {**APIM_INSTANCE, "instanceLabel": "Salesforce SObject Reads"}
            )

        assert result["server_name"] == "Salesforce SObject Reads"

    def test_records_instance_provenance(self, client):
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET, _org(), APIM_INSTANCE)

        md = result["metadata"]
        assert md["anypoint_api_instance_id"] == 20943747
        assert md["anypoint_environment_id"] == ENV_ID
        assert md["anypoint_proxy_uri"] == "http://0.0.0.0:8081/orders-mcp"

    def test_lands_disabled(self, client):
        """Imports must not be live until an operator enables them."""
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET, _org())
        assert result["is_enabled"] is False

    def test_stamps_provenance(self, client):
        """Reconciliation and cleanup depend on source plus Maven coordinates."""
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET, _org())

        assert result["source"] == "anypoint"
        assert result["is_read_only"] is True
        assert result["metadata"]["anypoint_asset_id"] == "omni-gateway-orders-mcp-server"
        assert result["metadata"]["anypoint_group_id"] == ORG_ID
        assert result["metadata"]["anypoint_version"] == "1.0.0"

    def test_path_is_namespaced_and_safe(self, client):
        with patch.object(client, "fetch_asset_metadata", return_value=MCP_METADATA):
            result = client.transform_mcp_asset(MCP_ASSET, _org())

        assert result["path"] == "/anypoint-omni-gateway-orders-mcp-server"

    def test_missing_metadata_still_produces_a_record(self, client):
        """An asset whose metadata file is gone must degrade, not crash."""
        with patch.object(client, "fetch_asset_metadata", return_value={}):
            result = client.transform_mcp_asset(MCP_ASSET, _org())

        assert result["num_tools"] == 0
        assert result["proxy_pass_url"] is None


class TestTransformA2aAsset:
    """The a2a type carries provenance only; the record is honestly sparse."""

    def test_records_provenance_without_inventing_fields(self, client):
        with patch.object(client, "fetch_asset_metadata", return_value=AGENT_METADATA):
            result = client.transform_a2a_asset(A2A_ASSET, _org())

        assert result["supported_protocol"] == "a2a"
        assert result["skills"] == [], "Exchange supplies no skills for a2a assets"
        assert result["url"] == "", "Exchange supplies no host"
        assert result["metadata"]["provenance"]["salesforce"]["platform"] == "Agentforce"
        assert result["metadata"]["discovery_only"] is True

    def test_generic_agent_type_is_not_a2a(self, client):
        """Only the a2a type declares a protocol we can act on."""
        asset = dict(A2A_ASSET, type="agent")
        with patch.object(client, "fetch_asset_metadata", return_value=AGENT_METADATA):
            result = client.transform_a2a_asset(asset, _org())

        assert result["supported_protocol"] == "other"

    def test_agent_path_is_namespaced(self, client):
        with patch.object(client, "fetch_asset_metadata", return_value=AGENT_METADATA):
            result = client.transform_a2a_asset(A2A_ASSET, _org())

        assert result["path"] == "/agents/anypoint-employee-a-2-a-aws-test"

    def test_lands_disabled(self, client):
        with patch.object(client, "fetch_asset_metadata", return_value=AGENT_METADATA):
            result = client.transform_a2a_asset(A2A_ASSET, _org())
        assert result["is_enabled"] is False


class TestBaseClientContract:
    """The name-keyed base methods do not apply to an enumerated catalog."""

    def test_fetch_server_is_unsupported(self, client):
        assert client.fetch_server("anything") is None

    def test_fetch_all_servers_is_unsupported(self, client):
        assert client.fetch_all_servers(["a", "b"]) == []


class TestConfigValidation:
    """Config-boundary validation, fail closed."""

    def test_rejects_plaintext_base_url(self):
        """The token request carries a secret, so https is mandatory."""
        with pytest.raises(ValueError, match="https"):
            AnypointFederationConfig(base_url="http://anypoint.mulesoft.com")

    def test_strips_trailing_slash(self):
        config = AnypointFederationConfig(base_url="https://anypoint.mulesoft.com/")
        assert config.base_url == "https://anypoint.mulesoft.com"

    def test_rejects_unknown_asset_type(self):
        """Silently importing nothing is worse than a clear error."""
        with pytest.raises(ValueError, match="Unsupported"):
            AnypointOrgConfig(org_id=ORG_ID, asset_types=["mcp", "rest-api"])

    def test_defaults_to_protocol_typed_assets(self):
        assert AnypointOrgConfig(org_id=ORG_ID).asset_types == ["mcp", "a2a"]

    def test_disabled_by_default(self):
        """A new source must never sync until explicitly enabled."""
        config = AnypointFederationConfig()
        assert config.enabled is False
        assert config.sync_on_startup is False
        assert config.organizations == []

    def test_requires_org_id(self):
        with pytest.raises(ValueError):
            AnypointOrgConfig(org_id="")

    def test_credentials_are_env_var_names_not_values(self):
        """The config must reference credentials, never carry them."""
        fields = set(AnypointOrgConfig.model_fields)
        assert "client_id_env_var" in fields
        assert "client_secret_env_var" in fields
        assert "client_secret" not in fields
        assert "client_id" not in fields

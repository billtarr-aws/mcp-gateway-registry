OAuth 2.1 Client ID Metadata Document (CIMD) for connecting an MCP client to
https://mcp.tableau.com

Tableau advertises client_id_metadata_document_supported=true and offers no
dynamic client registration, so a client identifies itself by URL. The
client_id in the JSON must equal the URL this file is served from.

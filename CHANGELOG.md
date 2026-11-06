# Changelog

## 0.3.0

- Map HTTP 409 to `SurfaceRevisionRejected` and preserve status-based failure categories.
- Check all local DNS answers before each relay HTTP leg, alongside the required trusted egress proxy. Use the shared explicit address range policy, including embedded IPv4 classification.
- Preserve explicit isolated local/unverified mode. DNS preflight does not pin the injected HTTP client's connection.

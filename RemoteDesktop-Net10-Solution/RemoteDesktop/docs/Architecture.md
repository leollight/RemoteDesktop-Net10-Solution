# Architecture & Security Design

## Separation of Planes
- **Control Plane (`RemoteDesktop.Backend` + SignalR + PostgreSQL):** Authoritative control plane handling user authentication (PBKDF2-SHA256 + JWT), ECDSA P-256 device identity challenge-response, RBAC permissions, session participant authorization, session state transitions, and immutable audit logs.
- **Media Plane (`RemoteDesktop.Media` + Coturn TURN):** Enforces `IceTransportPolicy = RelayOnly` across candidate trickling and `SelectedCandidatePairDto` (`local == relay` and `remote == relay`). Native capture (WGC/DXGI), audio (WASAPI), input injection (`SendInput`), and WebRTC transport integration remain explicit unimplemented stages in `MediaPipelineCapabilities` until native engines are bound.

## Explicit Device Enrolment & Session 0 Isolation
1. Devices generate a local ECDSA P-256 key pair protected by Windows DPAPI (`DataProtectionScope.LocalMachine`).
2. `RemoteDesktop.Host.Service.exe enrol --server <url> --token <token>` submits `DeviceRegistrationDto` over HTTPS using a single-use administrator-issued enrolment token and stores the backend-assigned `DeviceId`.
3. Newly enrolled devices start in `PendingApproval` with zero permissions and cannot authenticate until explicitly approved by an administrator.
4. `RemoteDesktop.Host.Service` (Session 0) communicates with visible `RemoteDesktop.Host.Agent` (active console session) over an ACL-restricted, PID/Session-ID verified, length-prefixed JSON Named Pipe protocol (`AgentIpcEnvelope`).

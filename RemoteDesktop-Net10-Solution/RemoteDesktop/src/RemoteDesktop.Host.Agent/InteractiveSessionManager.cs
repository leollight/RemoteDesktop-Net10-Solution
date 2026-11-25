using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RemoteDesktop.Contracts.Ipc;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Media;

namespace RemoteDesktop.Host.Agent;

public sealed class InteractiveSessionManager
{
    private readonly IInputInjector _inputInjector;
    private DevicePermission _activeSessionPermissions = DevicePermission.None;
    private Guid? _activeSessionId;

    public InteractiveSessionManager() : this(new UnimplementedInputInjector()) { }

    public InteractiveSessionManager(IInputInjector inputInjector)
    {
        _inputInjector = inputInjector;
    }

    public event Action<string>? StatusChanged;

    public DevicePermission ActiveSessionPermissions => _activeSessionPermissions;
    public Guid? ActiveSessionId => _activeSessionId;

    public void ApplyAuthorisedPermissions(Guid sessionId, DevicePermission grantedPermissions)
    {
        _activeSessionId = sessionId;
        _activeSessionPermissions = grantedPermissions;
    }

    public void RevokeActiveSession()
    {
        _activeSessionId = null;
        _activeSessionPermissions = DevicePermission.None;
    }

    public void DispatchMouseInput(int x, int y)
    {
        // Validates permission first, then delegates to real input injector (throws NotSupportedException while unimplemented).
        if (!InputValidator.IsMouseInputAllowed(_activeSessionPermissions))
            throw new UnauthorizedAccessException("ControlMouse permission is not granted.");

        _inputInjector.InjectMouseMoveOrClick(x, y, _activeSessionPermissions);
    }

    public async Task RunIpcClientLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var client = new NamedPipeClientStream(
                    ".",
                    "RemoteDesktop.Host.AgentIpc",
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous);

                await client.ConnectAsync(5000, cancellationToken);

                var secret = LoadLocalIpcSecret();
                var process = Process.GetCurrentProcess();
                var sessionId = process.SessionId;
                var username = Environment.UserName;
                var proof = ComputeIpcProof(secret, process.Id, sessionId, username);

                var caps = MediaPipelineCapabilities.Current;
                var hello = new AgentHelloPayload(
                    process.Id,
                    sessionId,
                    username,
                    proof,
                    caps.CaptureImplemented,
                    caps.InputInjectionImplemented,
                    caps.WebRtcMediaEngineImplemented);

                await WriteEnvelopeAsync(client, AgentIpcMessageType.AgentHello, hello, cancellationToken);
                var ackEnvelope = await ReadEnvelopeAsync(client, cancellationToken);
                if (ackEnvelope?.MessageType != AgentIpcMessageType.ServiceAck)
                    throw new InvalidOperationException("Host Service rejected agent IPC handshake.");

                var ack = JsonSerializer.Deserialize<ServiceAckPayload>(ackEnvelope.PayloadJson);
                if (ack is null || !ack.Accepted)
                    throw new InvalidOperationException(ack?.Message ?? "Agent IPC handshake rejected.");

                StatusChanged?.Invoke($"Connected to Host Service (DeviceId={ack.DeviceId})");

                using var hbCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var heartbeatTask = Task.Run(async () =>
                {
                    while (!hbCts.IsCancellationRequested && client.IsConnected)
                    {
                        await WriteEnvelopeAsync(
                            client,
                            AgentIpcMessageType.Heartbeat,
                            new AgentHeartbeatPayload(sessionId, _activeSessionId, DateTimeOffset.UtcNow),
                            hbCts.Token);
                        await Task.Delay(TimeSpan.FromSeconds(10), hbCts.Token);
                    }
                }, hbCts.Token);

                while (client.IsConnected && !cancellationToken.IsCancellationRequested)
                {
                    var envelope = await ReadEnvelopeAsync(client, cancellationToken);
                    if (envelope is null) break;

                    switch (envelope.MessageType)
                    {
                        case AgentIpcMessageType.SessionAuthorisationGrant:
                            var grant = JsonSerializer.Deserialize<SessionGrantPayload>(envelope.PayloadJson);
                            if (grant is not null)
                            {
                                ApplyAuthorisedPermissions(grant.SessionId, grant.GrantedPermissions);
                                StatusChanged?.Invoke($"Session {grant.SessionId} authorised ({grant.GrantedPermissions}).");
                                await WriteEnvelopeAsync(
                                    client,
                                    AgentIpcMessageType.MediaStatusReport,
                                    new MediaStatusPayload(
                                        grant.SessionId,
                                        caps.CaptureImplemented,
                                        caps.AudioImplemented,
                                        caps.InputInjectionImplemented,
                                        caps.WebRtcMediaEngineImplemented,
                                        caps.StatusNote),
                                    cancellationToken);
                            }
                            break;

                        case AgentIpcMessageType.SessionRevocationCommand:
                            RevokeActiveSession();
                            StatusChanged?.Invoke("Session revoked immediately by Host Service.");
                            break;
                    }
                }

                hbCts.Cancel();
                await heartbeatTask.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Awaiting Host Service IPC ({ex.Message})");
                await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);
            }
        }
    }

    private static string LoadLocalIpcSecret()
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var secretPath = Path.Combine(baseDir, "RemoteDesktop", "agent-ipc.key");
        if (!File.Exists(secretPath))
            throw new FileNotFoundException("Host Service IPC secret file not found; ensure Host Service is installed.", secretPath);
        return File.ReadAllText(secretPath).Trim();
    }

    private static string ComputeIpcProof(string secret, int pid, int sessionId, string username)
    {
        var data = Encoding.UTF8.GetBytes($"{pid}:{sessionId}:{username}");
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(hmac.ComputeHash(data));
    }

    private static async Task WriteEnvelopeAsync<T>(Stream stream, AgentIpcMessageType type, T payload, CancellationToken ct)
    {
        var envelope = new AgentIpcEnvelope(
            ProtocolVersion: 1,
            MessageType: type,
            CorrelationId: Guid.NewGuid().ToString("N"),
            TimestampUtc: DateTimeOffset.UtcNow,
            PayloadJson: JsonSerializer.Serialize(payload));

        var bodyBytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
        var lengthPrefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lengthPrefix, bodyBytes.Length);
        await stream.WriteAsync(lengthPrefix, ct);
        await stream.WriteAsync(bodyBytes, ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<AgentIpcEnvelope?> ReadEnvelopeAsync(Stream stream, CancellationToken ct)
    {
        var lengthBuf = new byte[4];
        var offset = 0;
        while (offset < 4)
        {
            var r = await stream.ReadAsync(lengthBuf.AsMemory(offset, 4 - offset), ct);
            if (r == 0) return null;
            offset += r;
        }

        var len = BinaryPrimitives.ReadInt32LittleEndian(lengthBuf);
        if (len is <= 0 or > 1_048_576)
            throw new InvalidDataException($"Invalid IPC frame length {len}.");

        var body = new byte[len];
        offset = 0;
        while (offset < len)
        {
            var r = await stream.ReadAsync(body.AsMemory(offset, len - offset), ct);
            if (r == 0) throw new EndOfStreamException("IPC stream closed mid-frame.");
            offset += r;
        }

        return JsonSerializer.Deserialize<AgentIpcEnvelope>(body);
    }
}

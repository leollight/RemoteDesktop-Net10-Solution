using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR.Client;
using RemoteDesktop.Contracts.Authentication;
using RemoteDesktop.Contracts.Ipc;
using RemoteDesktop.Contracts.Sessions;
using RemoteDesktop.Host.Service.Configuration;
using RemoteDesktop.Security;

namespace RemoteDesktop.Host.Service;

public sealed class HostWorker : BackgroundService
{
    private readonly ILogger<HostWorker> _logger;
    private readonly DeviceConfiguration _config;
    private readonly PortableDeviceConfigStore _configStore;
    private readonly IDeviceIdentityService _identityService;
    private readonly IHttpClientFactory _httpClientFactory;

    private string? _accessToken;
    private DateTimeOffset _tokenExpiresAt;
    private HubConnection? _hubConnection;
    private NamedPipeServerStream? _activeAgentPipe;
    private readonly SemaphoreSlim _pipeWriteLock = new(1, 1);

    public HostWorker(
        ILogger<HostWorker> logger,
        DeviceConfiguration config,
        PortableDeviceConfigStore configStore,
        IDeviceIdentityService identityService,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _config = config;
        _configStore = configStore;
        _identityService = identityService;
        _httpClientFactory = httpClientFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "RemoteDesktop Host Service starting for DeviceId={DeviceId}, Backend={Backend}.",
            _config.DeviceId,
            _config.BackendBaseUrl);

        var pipeTask = RunAgentIpcServerLoopAsync(stoppingToken);
        var controlTask = RunBackendAuthAndSignallingLoopAsync(stoppingToken);

        await Task.WhenAll(pipeTask, controlTask);
    }

    private async Task RunBackendAuthAndSignallingLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_accessToken is null || _tokenExpiresAt <= DateTimeOffset.UtcNow.AddMinutes(5))
                {
                    var authResult = await AuthenticateDeviceAsync(stoppingToken);
                    if (!authResult.Authenticated)
                    {
                        if (authResult.IsRevoked)
                        {
                            _logger.LogError("Device has been REVOKED by administrator. Halting session acceptance.");
                            await BroadcastToAgentAsync(
                                AgentIpcMessageType.SessionRevocationCommand,
                                new SessionRevokePayload(Guid.Empty, "Device revoked by administrator"),
                                stoppingToken);
                            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                            continue;
                        }

                        _logger.LogWarning("Device authentication deferred: {Reason}. Retrying in 15s.", authResult.Reason);
                        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
                        continue;
                    }
                }

                if (_hubConnection is null || _hubConnection.State == HubConnectionState.Disconnected)
                {
                    await ConnectSignallingHubAsync(stoppingToken);
                }

                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Host Service backend control loop; retrying in 15s.");
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }
    }

    private async Task<(bool Authenticated, bool IsRevoked, string Reason)> AuthenticateDeviceAsync(CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient();
        client.BaseAddress = new Uri(_config.BackendBaseUrl.TrimEnd('/'));
        var deviceId = _config.DeviceId!.Value;

        using var challengeRes = await client.PostAsJsonAsync("/api/devices/challenge", new DeviceChallengeRequestDto(deviceId), ct);
        if (challengeRes.StatusCode == HttpStatusCode.Forbidden)
        {
            return (false, IsRevoked: true, "Device rejected or revoked during challenge.");
        }
        challengeRes.EnsureSuccessStatusCode();

        var challenge = await challengeRes.Content.ReadFromJsonAsync<DeviceChallengeDto>(cancellationToken: ct)
            ?? throw new InvalidOperationException("Empty challenge payload from backend.");

        var protectedKey = await File.ReadAllBytesAsync(_config.IdentityFilePath, ct);
        var nonceBytes = Convert.FromBase64String(challenge.NonceBase64);
        var signature = _identityService.SignChallenge(protectedKey, nonceBytes);

        var authReq = new DeviceChallengeResponseDto(deviceId, challenge.NonceBase64, Convert.ToBase64String(signature));
        using var authRes = await client.PostAsJsonAsync("/api/devices/authenticate", authReq, ct);

        if (authRes.StatusCode == HttpStatusCode.Forbidden)
        {
            var body = await authRes.Content.ReadAsStringAsync(ct);
            var revoked = body.Contains("revoked", StringComparison.OrdinalIgnoreCase);
            return (false, revoked, body);
        }

        authRes.EnsureSuccessStatusCode();
        var authDto = await authRes.Content.ReadFromJsonAsync<DeviceAuthResponseDto>(cancellationToken: ct)
            ?? throw new InvalidOperationException("Empty authentication response from backend.");

        _accessToken = authDto.AccessToken;
        _tokenExpiresAt = authDto.ExpiresAt;

        // Discover portable runtime config (non-secret relay metadata) from authenticated backend.
        await _configStore.FetchRuntimeConfigAsync(client, _config, _accessToken, ct);
        _logger.LogInformation("Device authenticated via ECDSA challenge-response (Token expires {ExpiresAt}).", _tokenExpiresAt);
        return (true, false, string.Empty);
    }

    private async Task ConnectSignallingHubAsync(CancellationToken ct)
    {
        if (_hubConnection is not null)
        {
            await _hubConnection.DisposeAsync();
        }

        var hubUrl = $"{_config.BackendBaseUrl.TrimEnd('/')}/hubs/signalling";
        _hubConnection = new HubConnectionBuilder()
            .WithUrl(hubUrl, options =>
            {
                options.AccessTokenProvider = () => Task.FromResult(_accessToken);
            })
            .WithAutomaticReconnect()
            .Build();

        _hubConnection.On<SessionTerminationDto>("SessionRevoked", async termination =>
        {
            _logger.LogWarning("Received SessionRevoked for {SessionId}: {Reason}", termination.SessionId, termination.Reason);
            await BroadcastToAgentAsync(
                AgentIpcMessageType.SessionRevocationCommand,
                new SessionRevokePayload(termination.SessionId, termination.Reason),
                CancellationToken.None);
        });

        await _hubConnection.StartAsync(ct);
        _logger.LogInformation("Host Service connected to SignalR hub.");
    }

    private async Task RunAgentIpcServerLoopAsync(CancellationToken stoppingToken)
    {
        var ipcSecret = PortableDeviceConfigStore.GetOrCreateIpcSharedSecret();

        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                var security = BuildRestrictedPipeSecurity();
                pipe = NamedPipeServerStreamAcl.Create(
                    "RemoteDesktop.Host.AgentIpc",
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    16384,
                    16384,
                    security);

                await pipe.WaitForConnectionAsync(stoppingToken);

                if (!VerifyConnectedAgentSession(pipe, out var clientPid, out var clientSessionId))
                {
                    _logger.LogWarning("Rejected unauthorized pipe client connection (PID={Pid}, Session={Session}).", clientPid, clientSessionId);
                    await pipe.DisposeAsync();
                    continue;
                }

                _activeAgentPipe = pipe;
                _logger.LogInformation("Interactive Agent connected on Named Pipe (PID={Pid}, WindowsSession={Session}).", clientPid, clientSessionId);

                var authenticated = await HandleAgentPipeSessionAsync(pipe, ipcSecret, stoppingToken);
                if (!authenticated)
                {
                    _logger.LogWarning("Agent pipe client failed IPC handshake.");
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Interactive Agent Named Pipe connection ended; awaiting reconnect.");
            }
            finally
            {
                _activeAgentPipe = null;
                if (pipe is not null)
                {
                    await pipe.DisposeAsync();
                }
            }

            await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
        }
    }

    private async Task<bool> HandleAgentPipeSessionAsync(
        NamedPipeServerStream pipe,
        string ipcSecret,
        CancellationToken ct)
    {
        var firstMessage = await ReadEnvelopeAsync(pipe, ct);
        if (firstMessage is null || firstMessage.MessageType != AgentIpcMessageType.AgentHello)
            return false;

        var hello = JsonSerializer.Deserialize<AgentHelloPayload>(firstMessage.PayloadJson);
        if (hello is null || !VerifyIpcProof(ipcSecret, hello))
        {
            await WriteEnvelopeAsync(
                pipe,
                AgentIpcMessageType.ServiceAck,
                new ServiceAckPayload(false, _config.DeviceId ?? Guid.Empty, "Invalid IPC authentication proof."),
                ct);
            return false;
        }

        await WriteEnvelopeAsync(
            pipe,
            AgentIpcMessageType.ServiceAck,
            new ServiceAckPayload(true, _config.DeviceId ?? Guid.Empty, "Host Service IPC authenticated."),
            ct);

        while (pipe.IsConnected && !ct.IsCancellationRequested)
        {
            var msg = await ReadEnvelopeAsync(pipe, ct);
            if (msg is null) break;

            switch (msg.MessageType)
            {
                case AgentIpcMessageType.Heartbeat:
                    var hb = JsonSerializer.Deserialize<AgentHeartbeatPayload>(msg.PayloadJson);
                    _logger.LogDebug("Agent heartbeat from Windows Session {SessionId}.", hb?.WindowsSessionId);
                    break;
                case AgentIpcMessageType.MediaStatusReport:
                    var media = JsonSerializer.Deserialize<MediaStatusPayload>(msg.PayloadJson);
                    _logger.LogInformation("Agent media status for {SessionId}: {Detail}", media?.SessionId, media?.Detail);
                    break;
            }
        }

        return true;
    }

    private async Task BroadcastToAgentAsync<T>(AgentIpcMessageType type, T payload, CancellationToken ct)
    {
        var pipe = _activeAgentPipe;
        if (pipe is null || !pipe.IsConnected) return;

        await _pipeWriteLock.WaitAsync(ct);
        try
        {
            if (pipe.IsConnected)
                await WriteEnvelopeAsync(pipe, type, payload, ct);
        }
        finally
        {
            _pipeWriteLock.Release();
        }
    }

    private static PipeSecurity BuildRestrictedPipeSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        // Interactive console logon session SID restricts pipe access to active local console interactive desktop users.
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        return security;
    }

    private static bool VerifyIpcProof(string ipcSecret, AgentHelloPayload hello)
    {
        try
        {
            var data = Encoding.UTF8.GetBytes($"{hello.ProcessId}:{hello.WindowsSessionId}:{hello.InteractiveUsername}");
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(ipcSecret));
            var expected = hmac.ComputeHash(data);
            var actual = Convert.FromBase64String(hello.NonceProofHmac);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyConnectedAgentSession(NamedPipeServerStream pipe, out uint pid, out uint sessionId)
    {
        pid = 0;
        sessionId = 0;
        if (!OperatingSystem.IsWindows())
            return true;

        var handle = pipe.SafePipeHandle.DangerousGetHandle();
        if (!GetNamedPipeClientProcessId(handle, out pid))
            return false;

        if (!ProcessIdToSessionId(pid, out sessionId))
            return false;

        var activeConsoleSession = WTSGetActiveConsoleSessionId();
        return sessionId != 0 && sessionId == activeConsoleSession;
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
        var read = await ReadExactAsync(stream, lengthBuf, ct);
        if (read == 0) return null;

        var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBuf);
        if (length is <= 0 or > 1_048_576)
            throw new InvalidDataException($"Invalid IPC frame length {length}.");

        var payloadBuf = new byte[length];
        if (await ReadExactAsync(stream, payloadBuf, ct) != length)
            return null;

        return JsonSerializer.Deserialize<AgentIpcEnvelope>(payloadBuf);
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct);
            if (bytesRead == 0)
                return offset == 0 ? 0 : throw new EndOfStreamException("Unexpected end of IPC stream.");
            offset += bytesRead;
        }
        return offset;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
}

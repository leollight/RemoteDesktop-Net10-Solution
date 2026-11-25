using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Signalling;

namespace RemoteDesktop.Media;

public enum IceTransportPolicy
{
    RelayOnly = 0
}

public static class TurnRelayConfiguration
{
    public static bool IsCandidateAllowed(string candidateLine, IceTransportPolicy policy)
    {
        if (policy != IceTransportPolicy.RelayOnly)
            throw new InvalidOperationException("Direct peer-to-peer ICE candidates are prohibited by architecture policy.");

        if (string.IsNullOrWhiteSpace(candidateLine))
            return false;

        // Parse RFC 5245 / RFC 8445 candidate attribute tokens strictly rather than loose substring matching.
        var tokens = candidateLine.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var i = 0; i < tokens.Length - 1; i++)
        {
            if (tokens[i].Equals("typ", StringComparison.OrdinalIgnoreCase))
            {
                return tokens[i + 1].Equals("relay", StringComparison.OrdinalIgnoreCase);
            }
        }

        return false;
    }

    public static RelayVerificationResultDto VerifySelectedCandidatePair(
        SelectedCandidatePairDto? pair,
        IceTransportPolicy policy)
    {
        if (policy != IceTransportPolicy.RelayOnly)
            return new RelayVerificationResultDto(false, "Direct peer-to-peer transport policy is prohibited.");

        if (pair is null)
            return new RelayVerificationResultDto(false, "Selected ICE candidate pair statistics were not provided.");

        if (!pair.PairState.Equals("succeeded", StringComparison.OrdinalIgnoreCase))
            return new RelayVerificationResultDto(false, $"Selected ICE candidate pair state '{pair.PairState}' is not succeeded.");

        if (!pair.LocalCandidateType.Equals("relay", StringComparison.OrdinalIgnoreCase)
            || !pair.RemoteCandidateType.Equals("relay", StringComparison.OrdinalIgnoreCase))
        {
            return new RelayVerificationResultDto(
                false,
                $"Relay-only policy rejected selected pair (local='{pair.LocalCandidateType}', remote='{pair.RemoteCandidateType}').");
        }

        if (string.IsNullOrWhiteSpace(pair.RelayServerAddress))
            return new RelayVerificationResultDto(false, "Relay server address is missing from selected candidate pair report.");

        return new RelayVerificationResultDto(true, $"Verified relay-only candidate pair via {pair.RelayServerAddress} ({pair.TransportProtocol}).");
    }
}

public sealed record MediaPipelineCapabilities(
    bool CaptureImplemented,
    bool AudioImplemented,
    bool InputInjectionImplemented,
    bool WebRtcMediaEngineImplemented,
    string StatusNote)
{
    public static MediaPipelineCapabilities Current { get; } = new(
        CaptureImplemented: false,
        AudioImplemented: false,
        InputInjectionImplemented: false,
        WebRtcMediaEngineImplemented: false,
        StatusNote: "Contracts, permission validation, and relay-only ICE enforcement are implemented; native WGC/DXGI capture, WASAPI audio, Win32 SendInput injection, and WebRTC media engine integration remain pending.");
}

public sealed record VideoFrame(int Width, int Height, long TimestampMs, ReadOnlyMemory<byte> BgraData);

public interface IScreenCapture : IAsyncDisposable
{
    string ProviderName { get; }
    bool IsSupported();
    Task InitializeAsync(int monitorIndex, CancellationToken cancellationToken);
    Task<VideoFrame?> CaptureNextFrameAsync(CancellationToken cancellationToken);
}

public sealed class CaptureManager
{
    private readonly IEnumerable<IScreenCapture> _providers;

    public CaptureManager(IEnumerable<IScreenCapture> providers) => _providers = providers;

    public async Task<IScreenCapture> SelectCaptureProviderAsync(int monitorIndex, CancellationToken cancellationToken)
    {
        foreach (var provider in _providers)
        {
            if (!provider.IsSupported()) continue;
            try
            {
                await provider.InitializeAsync(monitorIndex, cancellationToken);
                return provider;
            }
            catch
            {
                // Fall back to next capture provider
            }
        }
        throw new PlatformNotSupportedException("No screen capture provider is currently implemented/available on this host.");
    }
}

public interface IVideoEncoder : IDisposable
{
    string CodecName { get; }
    bool IsHardwareAccelerated { get; }
    bool IsAvailable();
    ReadOnlyMemory<byte> EncodeFrame(VideoFrame frame, int targetBitrateKbps);
}

public interface IInputInjector
{
    bool IsImplemented { get; }
    void InjectMouseMoveOrClick(int x, int y, DevicePermission grantedPermissions);
    void InjectKeyEvent(ushort virtualKeyCode, bool isKeyUp, DevicePermission grantedPermissions);
}

public sealed class UnimplementedInputInjector : IInputInjector
{
    public bool IsImplemented => false;

    public void InjectMouseMoveOrClick(int x, int y, DevicePermission grantedPermissions)
    {
        if (!InputValidator.IsMouseInputAllowed(grantedPermissions))
            throw new UnauthorizedAccessException("ControlMouse permission is not granted for this session.");

        throw new NotSupportedException("Win32 SendInput mouse injection is not yet implemented in this build.");
    }

    public void InjectKeyEvent(ushort virtualKeyCode, bool isKeyUp, DevicePermission grantedPermissions)
    {
        if (!InputValidator.IsKeyboardInputAllowed(grantedPermissions))
            throw new UnauthorizedAccessException("ControlKeyboard permission is not granted for this session.");

        throw new NotSupportedException("Win32 SendInput keyboard injection is not yet implemented in this build.");
    }
}

public static class InputValidator
{
    public static bool IsMouseInputAllowed(DevicePermission permissions) =>
        permissions.HasFlag(DevicePermission.ControlMouse);

    public static bool IsKeyboardInputAllowed(DevicePermission permissions) =>
        permissions.HasFlag(DevicePermission.ControlKeyboard);
}

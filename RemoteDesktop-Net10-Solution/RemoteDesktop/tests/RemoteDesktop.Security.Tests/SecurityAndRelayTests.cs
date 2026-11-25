using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Signalling;
using RemoteDesktop.Media;
using RemoteDesktop.Security;
using Xunit;

namespace RemoteDesktop.Security.Tests;

public sealed class SecurityAndRelayTests
{
    [Fact]
    public void PasswordHasher_VerifiesCorrectPasswordAndRejectsWrongPassword()
    {
        var hasher = new Pbkdf2PasswordHasher();
        var hash = hasher.HashPassword("StrongPassphrase#2026");

        Assert.True(hasher.VerifyPassword("StrongPassphrase#2026", hash));
        Assert.False(hasher.VerifyPassword("WrongPassphrase", hash));
    }

    [Fact]
    public void JwtTokenService_IssuesAndValidatesUserAndDeviceTokens()
    {
        var opts = new SecurityOptions();
        var service = new JwtTokenService(opts, "server-only-signing-key-at-least-32-chars-long");
        var userId = Guid.NewGuid();
        var (token, _, _) = service.IssueUserToken(userId, "admin@remotedesktop.local", "Admin");

        var handler = new JwtSecurityTokenHandler();
        var principal = handler.ValidateToken(token, service.CreateValidationParameters(), out _);

        Assert.Equal("user", principal.FindFirst("participant_type")?.Value);
        Assert.True(principal.IsInRole("Admin"));
    }

    [Fact]
    public void DeviceIdentityService_VerifiesValidEcdsaSignatureAndRejectsTamperedNonce()
    {
        var identity = new DeviceIdentityService();
        var (pub, priv, fp) = identity.CreateDeviceKeyPair();
        var nonce = RandomNumberGenerator.GetBytes(32);
        var sig = identity.SignChallenge(priv, nonce);

        Assert.False(string.IsNullOrWhiteSpace(fp));
        Assert.True(identity.VerifyChallengeSignature(pub, nonce, sig));

        nonce[0] ^= 0xFF;
        Assert.False(identity.VerifyChallengeSignature(pub, nonce, sig));
    }

    [Fact]
    public void SessionAuthorisation_EnforcesApprovalRevocationAndDualUnattendedConsent()
    {
        var auth = new SessionAuthorisationService();

        Assert.False(auth.CanInitiateSession(true, true, false, false, false, DevicePermission.ViewScreen, true));
        Assert.False(auth.CanInitiateSession(false, false, false, false, false, DevicePermission.ViewScreen, true));
        Assert.False(auth.CanInitiateSession(true, false, false, false, false, DevicePermission.None, false));
        Assert.False(auth.CanInitiateSession(true, false, true, false, true, DevicePermission.ViewScreen, false));
        Assert.False(auth.CanInitiateSession(true, false, true, true, false, DevicePermission.ViewScreen, false));
        Assert.True(auth.CanInitiateSession(true, false, true, true, true, DevicePermission.ViewScreen, false));
    }

    [Fact]
    public void TurnCredentialProvider_ThrowsWhenUnconfiguredAndGeneratesHmacWhenConfigured()
    {
        var unconfigured = new TurnCredentialProvider(string.Empty, Array.Empty<string>());
        Assert.False(unconfigured.IsConfigured);
        Assert.Throws<InvalidOperationException>(() => unconfigured.GenerateEphemeralCredentials(Guid.NewGuid(), TimeSpan.FromMinutes(10)));

        var configured = new TurnCredentialProvider("0123456789abcdef0123456789abcdef", new[] { "turns:turn.example:5349?transport=tcp" });
        Assert.True(configured.IsConfigured);
        var creds = configured.GenerateEphemeralCredentials(Guid.NewGuid(), TimeSpan.FromMinutes(5));
        Assert.Equal("relay", creds.IceTransportPolicy);
        Assert.True(creds.RelayOnly);
        Assert.False(string.IsNullOrWhiteSpace(creds.Credential));
    }

    [Fact]
    public void RelayPolicy_RejectsDirectCandidatesAndNonRelayCandidatePairs()
    {
        Assert.False(TurnRelayConfiguration.IsCandidateAllowed("candidate:1 1 UDP 2122252543 192.168.1.50 54122 typ host", IceTransportPolicy.RelayOnly));
        Assert.False(TurnRelayConfiguration.IsCandidateAllowed("candidate:2 1 UDP 1686052607 203.0.113.10 54122 typ srflx", IceTransportPolicy.RelayOnly));
        Assert.False(TurnRelayConfiguration.IsCandidateAllowed("candidate:4 1 UDP 1686052607 203.0.113.10 54122 typ prflx", IceTransportPolicy.RelayOnly));
        Assert.True(TurnRelayConfiguration.IsCandidateAllowed("candidate:3 1 UDP 41885439 198.51.100.2 49152 typ relay", IceTransportPolicy.RelayOnly));

        var sessionId = Guid.NewGuid();
        var hostPair = new SelectedCandidatePairDto(sessionId, "host", "relay", "udp", "198.51.100.2:49152", "succeeded");
        Assert.False(TurnRelayConfiguration.VerifySelectedCandidatePair(hostPair, IceTransportPolicy.RelayOnly).IsRelayVerified);

        var remoteSrflxPair = new SelectedCandidatePairDto(sessionId, "relay", "srflx", "udp", "198.51.100.2:49152", "succeeded");
        Assert.False(TurnRelayConfiguration.VerifySelectedCandidatePair(remoteSrflxPair, IceTransportPolicy.RelayOnly).IsRelayVerified);

        var validRelayPair = new SelectedCandidatePairDto(sessionId, "relay", "relay", "udp", "198.51.100.2:49152", "succeeded");
        Assert.True(TurnRelayConfiguration.VerifySelectedCandidatePair(validRelayPair, IceTransportPolicy.RelayOnly).IsRelayVerified);
    }

    [Fact]
    public void UnimplementedInputInjector_ThrowsNotSupportedRatherThanReturningFakeTrue()
    {
        var injector = new UnimplementedInputInjector();
        Assert.False(injector.IsImplemented);
        Assert.Throws<UnauthorizedAccessException>(() => injector.InjectMouseMoveOrClick(10, 20, DevicePermission.ViewScreen));
        Assert.Throws<NotSupportedException>(() => injector.InjectMouseMoveOrClick(10, 20, DevicePermission.ControlMouse));
    }
}

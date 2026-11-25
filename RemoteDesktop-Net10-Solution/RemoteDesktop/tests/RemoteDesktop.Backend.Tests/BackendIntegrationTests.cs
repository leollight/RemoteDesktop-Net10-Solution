using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RemoteDesktop.Contracts.Authentication;
using RemoteDesktop.Contracts.Configuration;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Sessions;
using RemoteDesktop.Contracts.Signalling;
using RemoteDesktop.Infrastructure.Persistence;
using RemoteDesktop.Security;
using Xunit;

namespace RemoteDesktop.Backend.Tests;

public sealed class BackendTestFactory : WebApplicationFactory<Program>
{
    private readonly string _dbName = $"rdp-test-{Guid.NewGuid():N}";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Testing:UseInMemoryDatabase"] = "true",
                ["Security:SessionSecret"] = "test-signing-key-with-more-than-32-characters-0123456789",
                ["Relay:Host"] = "turn.test.local",
                ["Relay:Port"] = "3478",
                ["Relay:Transport"] = "udp",
                ["Relay:Realm"] = "turn.test.local",
                ["Relay:SharedSecret"] = "0123456789abcdef0123456789abcdef",
                ["Development:AllowUnconfiguredTurnForNonMediaStages"] = "true"
            });
        });

        builder.ConfigureServices(services =>
        {
            services.AddDbContext<ApplicationDbContext>(opt => opt.UseInMemoryDatabase(_dbName));
        });
    }
}

public sealed class BackendIntegrationTests
{
    [Fact]
    public async Task ProtectedEndpoint_RejectsUnauthenticatedCaller()
    {
        await using var factory = new BackendTestFactory();
        using var client = factory.CreateClient();

        var res = await client.GetAsync("/api/config/runtime");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task AdminSetup_EnrolmentApprovalChallengeRevocation_AndSignallingIsolation_WorkEndToEnd()
    {
        await using var factory = new BackendTestFactory();
        using var client = factory.CreateClient();

        // 1. First-run administrator claim
        var setupRes = await client.PostAsJsonAsync("/api/auth/setup", new AdminSetupRequestDto(
            "admin@remotedesktop.local",
            "Primary Admin",
            "AdminPassphrase#2026"));
        Assert.Equal(HttpStatusCode.Created, setupRes.StatusCode);
        var adminAuth = await setupRes.Content.ReadFromJsonAsync<LoginResponseDto>();
        Assert.NotNull(adminAuth);

        // Runtime config must never expose TURN_SHARED_SECRET
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminAuth!.AccessToken);
        var runtimeConfig = await client.GetFromJsonAsync<RuntimeConfigurationDto>("/api/config/runtime");
        Assert.NotNull(runtimeConfig);
        Assert.True(runtimeConfig!.TurnConfigured);
        Assert.Equal("turn.test.local", runtimeConfig.Turn!.Host);

        // 2. Create an unauthorized second user (Operator2) who will later try hijacking a sessionId
        var user2Res = await client.PostAsJsonAsync("/api/users", new CreateUserRequestDto(
            "outsider@remotedesktop.local",
            "Outsider Operator",
            "Operator",
            "OutsiderPass#2026"));
        Assert.Equal(HttpStatusCode.Created, user2Res.StatusCode);

        var user2LoginRes = await client.PostAsJsonAsync("/api/auth/login", new LoginRequestDto(
            "outsider@remotedesktop.local",
            "OutsiderPass#2026",
            null));
        var outsiderAuth = await user2LoginRes.Content.ReadFromJsonAsync<LoginResponseDto>();
        Assert.NotNull(outsiderAuth);

        // 3. Issue single-use enrolment token and enrol device with ECDSA P-256 key
        var tokenRes = await client.PostAsync("/api/devices/enrolment-token", null);
        Assert.Equal(HttpStatusCode.Created, tokenRes.StatusCode);
        var enrolmentToken = await tokenRes.Content.ReadFromJsonAsync<EnrolmentTokenDto>();
        Assert.NotNull(enrolmentToken);

        var identityService = new DeviceIdentityService();
        var (pubKey, privKey, _) = identityService.CreateDeviceKeyPair();

        using var anonClient = factory.CreateClient();
        var enrolRes = await anonClient.PostAsJsonAsync("/api/devices/enrol", new DeviceRegistrationDto(
            "WORKSTATION-01",
            "Windows 11 Pro",
            "1.0.0",
            pubKey,
            enrolmentToken!.Token,
            new DeviceCapabilitiesDto(1, true, true, "Pending", false, false)));
        Assert.Equal(HttpStatusCode.Created, enrolRes.StatusCode);
        var enrolledDevice = await enrolRes.Content.ReadFromJsonAsync<DeviceDto>();
        Assert.NotNull(enrolledDevice);
        Assert.Equal(DeviceStatus.PendingApproval, enrolledDevice!.Status);
        Assert.False(enrolledDevice.IsApproved);

        // PendingApproval device MUST be rejected during challenge-response authentication
        var pendingChallengeRes = await anonClient.PostAsJsonAsync("/api/devices/challenge", new DeviceChallengeRequestDto(enrolledDevice.Id));
        var pendingChallenge = await pendingChallengeRes.Content.ReadFromJsonAsync<DeviceChallengeDto>();
        var pendingSig = identityService.SignChallenge(privKey, Convert.FromBase64String(pendingChallenge!.NonceBase64));
        var pendingAuthRes = await anonClient.PostAsJsonAsync("/api/devices/authenticate",
            new DeviceChallengeResponseDto(enrolledDevice.Id, pendingChallenge.NonceBase64, Convert.ToBase64String(pendingSig)));
        Assert.Equal(HttpStatusCode.Forbidden, pendingAuthRes.StatusCode);

        // 4. Approve device & authenticate via ECDSA challenge-response
        var approveRes = await client.PostAsync($"/api/devices/{enrolledDevice.Id}/approve", null);
        Assert.Equal(HttpStatusCode.OK, approveRes.StatusCode);

        var challengeRes = await anonClient.PostAsJsonAsync("/api/devices/challenge", new DeviceChallengeRequestDto(enrolledDevice.Id));
        var challenge = await challengeRes.Content.ReadFromJsonAsync<DeviceChallengeDto>();
        var sig = identityService.SignChallenge(privKey, Convert.FromBase64String(challenge!.NonceBase64));
        var devAuthRes = await anonClient.PostAsJsonAsync("/api/devices/authenticate",
            new DeviceChallengeResponseDto(enrolledDevice.Id, challenge.NonceBase64, Convert.ToBase64String(sig)));
        Assert.Equal(HttpStatusCode.OK, devAuthRes.StatusCode);
        var deviceAuth = await devAuthRes.Content.ReadFromJsonAsync<DeviceAuthResponseDto>();
        Assert.NotNull(deviceAuth);

        // 5. Admin authorises session
        var sessRes = await client.PostAsJsonAsync("/api/sessions", new SessionRequestDto(
            enrolledDevice.Id,
            null,
            "CONTROLLER-PC",
            RequestUnattended: false));
        Assert.Equal(HttpStatusCode.Created, sessRes.StatusCode);
        var session = await sessRes.Content.ReadFromJsonAsync<SessionDto>();
        Assert.NotNull(session);

        // 6. Outsider who merely knows session.Id CANNOT fetch TURN creds or join SignalR channel
        using var outsiderClient = factory.CreateClient();
        outsiderClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", outsiderAuth!.AccessToken);
        var outsiderTurn = await outsiderClient.PostAsync($"/api/sessions/{session!.Id}/turn-credentials", null);
        Assert.Equal(HttpStatusCode.Forbidden, outsiderTurn.StatusCode);

        var hubUri = new Uri(factory.Server.BaseAddress, "/hubs/signalling");
        await using var outsiderHub = new HubConnectionBuilder()
            .WithUrl(hubUri, opt =>
            {
                opt.HttpMessageHandlerFactory = _ => factory.Server.CreateHandler();
                opt.AccessTokenProvider = () => Task.FromResult<string?>(outsiderAuth.AccessToken);
            })
            .Build();
        await outsiderHub.StartAsync();
        await Assert.ThrowsAsync<HubException>(() => outsiderHub.InvokeAsync("JoinSessionChannel", session.Id));

        // 7. Authorised controller CAN join SignalR and non-relay candidates/pairs are rejected
        await using var adminHub = new HubConnectionBuilder()
            .WithUrl(hubUri, opt =>
            {
                opt.HttpMessageHandlerFactory = _ => factory.Server.CreateHandler();
                opt.AccessTokenProvider = () => Task.FromResult<string?>(adminAuth.AccessToken);
            })
            .Build();
        await adminHub.StartAsync();
        await adminHub.InvokeAsync("JoinSessionChannel", session.Id);

        await Assert.ThrowsAsync<HubException>(() => adminHub.InvokeAsync(
            "ForwardIceCandidate",
            new IceCandidateDto(session.Id, "candidate:1 1 UDP 2122252543 192.168.1.10 50000 typ host", "0", 0, "host")));

        var relayConnRes = await client.PostAsJsonAsync($"/api/sessions/{session.Id}/transition",
            new TransitionSessionRequestDto(SessionState.RelayConnecting, null, "Start TURN"));
        Assert.Equal(HttpStatusCode.OK, relayConnRes.StatusCode);

        // Direct P2P selected candidate pair must fail Connected transition
        var badConnectRes = await client.PostAsJsonAsync($"/api/sessions/{session.Id}/transition",
            new TransitionSessionRequestDto(
                SessionState.Connected,
                new SelectedCandidatePairDto(session.Id, "srflx", "relay", "udp", "198.51.100.2:49152", "succeeded"),
                "Attempt direct"));
        Assert.Equal(HttpStatusCode.BadRequest, badConnectRes.StatusCode);

        // 8. Start a second session and verify device revocation terminates it & blocks re-auth
        var sess2Res = await client.PostAsJsonAsync("/api/sessions", new SessionRequestDto(
            enrolledDevice.Id, null, "CONTROLLER-PC", false));
        var session2 = await sess2Res.Content.ReadFromJsonAsync<SessionDto>();

        var revokeRes = await client.PostAsync($"/api/devices/{enrolledDevice.Id}/revoke", null);
        Assert.Equal(HttpStatusCode.OK, revokeRes.StatusCode);

        var sessionsAfter = await client.GetFromJsonAsync<List<SessionDto>>("/api/sessions");
        Assert.Contains(sessionsAfter!, s => s.Id == session2!.Id && s.State == SessionState.Revoked);

        var revokedChallenge = await anonClient.PostAsJsonAsync("/api/devices/challenge", new DeviceChallengeRequestDto(enrolledDevice.Id));
        Assert.Equal(HttpStatusCode.Forbidden, revokedChallenge.StatusCode);
    }
}

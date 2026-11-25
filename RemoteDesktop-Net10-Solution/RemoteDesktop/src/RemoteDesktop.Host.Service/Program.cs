using System.Net.Http.Json;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Host.Service;
using RemoteDesktop.Host.Service.Configuration;
using RemoteDesktop.Security;

var store = new PortableDeviceConfigStore();

if (args.Length > 0 && args[0].Equals("enrol", StringComparison.OrdinalIgnoreCase))
{
    string? serverUrl = null;
    string? token = null;

    for (var i = 1; i < args.Length - 1; i++)
    {
        if (args[i] == "--server") serverUrl = args[i + 1];
        if (args[i] == "--token") token = args[i + 1];
    }

    if (string.IsNullOrWhiteSpace(serverUrl) || !Uri.TryCreate(serverUrl, UriKind.Absolute, out _) || string.IsNullOrWhiteSpace(token))
    {
        Console.Error.WriteLine("Usage: RemoteDesktop.Host.Service.exe enrol --server <https://backend-url> --token <enrolment-token>");
        return 1;
    }

    var identityService = new DeviceIdentityService();
    var (publicKeyBase64, protectedPrivateKey, fingerprint) = identityService.CreateDeviceKeyPair();

    var registrationPayload = new DeviceRegistrationDto(
        DisplayName: Environment.MachineName,
        OperatingSystem: Environment.OSVersion.VersionString,
        AppVersion: typeof(HostWorker).Assembly.GetName().Version?.ToString() ?? "1.0.0",
        PublicKeyBase64: publicKeyBase64,
        EnrolmentToken: token.Trim(),
        Capabilities: new DeviceCapabilitiesDto(
            MonitorCount: 1,
            SupportsWindowsGraphicsCapture: OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362),
            SupportsDxgiDuplication: OperatingSystem.IsWindows(),
            PreferredEncoder: "PendingMediaEngineIntegration",
            SupportsHardwareEncoding: false,
            SupportsAudioCapture: false));

    using var httpClient = new HttpClient { BaseAddress = new Uri(serverUrl.TrimEnd('/')) };
    using var response = await httpClient.PostAsJsonAsync("/api/devices/enrol", registrationPayload);
    if (!response.IsSuccessStatusCode)
    {
        var errBody = await response.Content.ReadAsStringAsync();
        Console.Error.WriteLine($"Enrolment failed ({(int)response.StatusCode}): {errBody}");
        return 2;
    }

    var registeredDevice = await response.Content.ReadFromJsonAsync<DeviceDto>();
    if (registeredDevice is null || registeredDevice.Id == Guid.Empty)
    {
        Console.Error.WriteLine("Backend returned an invalid device registration payload.");
        return 3;
    }

    var identityPath = PortableDeviceConfigStore.GetIdentityKeyFilePath();
    await File.WriteAllBytesAsync(identityPath, protectedPrivateKey);

    var config = store.LoadOrCreate();
    config.BackendBaseUrl = serverUrl.TrimEnd('/');
    config.DeviceId = registeredDevice.Id;
    config.DeviceDisplayName = registeredDevice.DisplayName;
    config.PublicKeyFingerprint = registeredDevice.PublicKeyFingerprint;
    config.IdentityFilePath = identityPath;
    store.Save(config);

    Console.WriteLine($"Submitted enrolment for {config.DeviceDisplayName} (DeviceId={config.DeviceId}, Fingerprint={fingerprint}).");
    Console.WriteLine("Status: PendingApproval. An administrator must approve this device before sessions are permitted.");
    return 0;
}

var deviceConfig = store.LoadOrCreate();
store.ValidateForServiceStartup(deviceConfig);

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "RemoteDesktopHostService");
builder.Services.AddSingleton(store);
builder.Services.AddSingleton(deviceConfig);
builder.Services.AddSingleton<IDeviceIdentityService, DeviceIdentityService>();
builder.Services.AddHttpClient();
builder.Services.AddHostedService<HostWorker>();

var host = builder.Build();
await host.RunAsync();
return 0;

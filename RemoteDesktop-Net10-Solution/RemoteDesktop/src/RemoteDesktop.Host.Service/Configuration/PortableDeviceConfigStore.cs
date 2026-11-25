using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using RemoteDesktop.Contracts.Configuration;

namespace RemoteDesktop.Host.Service.Configuration;

public sealed class DeviceConfiguration
{
    public string BackendBaseUrl { get; set; } = string.Empty;
    public Guid? DeviceId { get; set; }
    public string DeviceDisplayName { get; set; } = Environment.MachineName;
    public string PublicKeyFingerprint { get; set; } = string.Empty;
    public string IdentityFilePath { get; set; } = string.Empty;
}

public sealed class PortableDeviceConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string GetMachineDataDirectory()
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var appDir = Path.Combine(baseDir, "RemoteDesktop");
        Directory.CreateDirectory(appDir);
        return appDir;
    }

    public static string GetConfigFilePath() => Path.Combine(GetMachineDataDirectory(), "device-config.json");

    public static string GetIdentityKeyFilePath() => Path.Combine(GetMachineDataDirectory(), "device-identity.dat");

    public static string GetOrCreateIpcSharedSecret()
    {
        var secretPath = Path.Combine(GetMachineDataDirectory(), "agent-ipc.key");
        if (File.Exists(secretPath))
        {
            var existing = File.ReadAllText(secretPath).Trim();
            if (existing.Length >= 32)
                return existing;
        }

        var generated = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        File.WriteAllText(secretPath, generated);
        return generated;
    }

    public DeviceConfiguration LoadOrCreate()
    {
        var path = GetConfigFilePath();
        if (!File.Exists(path))
        {
            var initial = new DeviceConfiguration
            {
                DeviceDisplayName = Environment.MachineName,
                IdentityFilePath = GetIdentityKeyFilePath()
            };
            Save(initial);
            return initial;
        }

        var loaded = JsonSerializer.Deserialize<DeviceConfiguration>(File.ReadAllText(path)) ?? new DeviceConfiguration();
        if (string.IsNullOrWhiteSpace(loaded.DeviceDisplayName))
            loaded.DeviceDisplayName = Environment.MachineName;
        if (string.IsNullOrWhiteSpace(loaded.IdentityFilePath))
            loaded.IdentityFilePath = GetIdentityKeyFilePath();
        return loaded;
    }

    public void Save(DeviceConfiguration config)
    {
        File.WriteAllText(GetConfigFilePath(), JsonSerializer.Serialize(config, JsonOptions));
    }

    public void ValidateForServiceStartup(DeviceConfiguration config)
    {
        if (string.IsNullOrWhiteSpace(config.BackendBaseUrl) || !Uri.TryCreate(config.BackendBaseUrl, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException(
                $"Host configuration is incomplete ({GetConfigFilePath()}). Run 'RemoteDesktop.Host.Service.exe enrol --server <backend-url> --token <enrolment-token>' to enrol this PC.");
        }

        if (config.DeviceId is null || config.DeviceId == Guid.Empty)
        {
            throw new InvalidOperationException(
                "DeviceId has not been assigned by the backend yet. Re-run explicit device enrolment with a valid enrolment token.");
        }

        if (!File.Exists(config.IdentityFilePath))
        {
            throw new InvalidOperationException(
                "Device cryptographic identity key file is missing. Run explicit device enrolment first.");
        }
    }

    public async Task<RuntimeConfigurationDto?> FetchRuntimeConfigAsync(
        HttpClient httpClient,
        DeviceConfiguration config,
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{config.BackendBaseUrl.TrimEnd('/')}/api/config/runtime");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var res = await httpClient.SendAsync(req, cancellationToken);
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadFromJsonAsync<RuntimeConfigurationDto>(cancellationToken: cancellationToken);
    }
}

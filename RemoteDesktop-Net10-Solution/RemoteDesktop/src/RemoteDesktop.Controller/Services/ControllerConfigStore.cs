using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using RemoteDesktop.Contracts.Configuration;

namespace RemoteDesktop.Controller.Services;

public sealed class ControllerConfiguration
{
    public string BackendBaseUrl { get; set; } = string.Empty;
    public string ControllerDeviceName { get; set; } = Environment.MachineName;
}

public sealed class ControllerConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string GetConfigPath()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "RemoteDesktop");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "controller-config.json");
    }

    public ControllerConfiguration Load()
    {
        var path = GetConfigPath();
        if (!File.Exists(path))
            return new ControllerConfiguration { ControllerDeviceName = Environment.MachineName };

        return JsonSerializer.Deserialize<ControllerConfiguration>(File.ReadAllText(path))
            ?? new ControllerConfiguration { ControllerDeviceName = Environment.MachineName };
    }

    public void Save(ControllerConfiguration config)
    {
        File.WriteAllText(GetConfigPath(), JsonSerializer.Serialize(config, JsonOptions));
    }

    public async Task<RuntimeConfigurationDto> DiscoverRuntimeConfigAsync(
        HttpClient httpClient,
        string backendBaseUrl,
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(backendBaseUrl) || !Uri.TryCreate(backendBaseUrl, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException("Enter a valid Backend Server URL in Controller settings before connecting.");
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, $"{backendBaseUrl.TrimEnd('/')}/api/config/runtime");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var res = await httpClient.SendAsync(req, cancellationToken);
        res.EnsureSuccessStatusCode();

        var dto = await res.Content.ReadFromJsonAsync<RuntimeConfigurationDto>(cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Backend returned an empty runtime configuration.");

        if (dto.TurnConfigured && dto.Turn is null)
            throw new InvalidOperationException("Backend reported TURN configured but omitted relay endpoint details.");

        return dto;
    }
}

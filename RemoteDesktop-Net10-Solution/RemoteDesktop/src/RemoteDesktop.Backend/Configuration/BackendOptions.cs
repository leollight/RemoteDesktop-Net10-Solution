using System.Security.Cryptography;
using RemoteDesktop.Contracts.Configuration;

namespace RemoteDesktop.Backend.Configuration;

public sealed class RelayOptions
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 3478;
    public string Transport { get; set; } = "udp";
    public string Realm { get; set; } = "remotedesktop.local";
    public bool RelayOnly { get; set; } = true;
    public string SharedSecret { get; set; } = string.Empty;
    public string PublicBaseUrl { get; set; } = string.Empty;

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Host)
        && Port is > 0 and < 65536
        && !string.IsNullOrWhiteSpace(Realm)
        && !string.IsNullOrWhiteSpace(SharedSecret)
        && SharedSecret.Length >= 32;

    public IReadOnlyList<string> BuildTurnUris()
    {
        if (string.IsNullOrWhiteSpace(Host) || Port is <= 0 or >= 65536)
            return Array.Empty<string>();

        var transport = (Transport ?? "udp").Trim().ToLowerInvariant();
        if (transport == "tls")
        {
            return new[] { $"turns:{Host.Trim()}:{Port}?transport=tcp" };
        }

        var normalizedTransport = transport == "tcp" ? "tcp" : "udp";
        return new[] { $"turn:{Host.Trim()}:{Port}?transport={normalizedTransport}" };
    }
}

public sealed record StartupValidationResult(
    bool IsValid,
    bool TurnConfigured,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Errors);

public static class ServerSecretProvisioner
{
    public static string LoadOrProvisionSigningKey(IConfiguration configuration, string contentRootPath)
    {
        var fromConfig = configuration["Security:SessionSecret"]
            ?? Environment.GetEnvironmentVariable("SESSION_SECRET");

        if (!string.IsNullOrWhiteSpace(fromConfig) && fromConfig.Trim().Length >= 32)
            return fromConfig.Trim();

        var secretsDir = Path.Combine(contentRootPath, "App_Data");
        Directory.CreateDirectory(secretsDir);
        var keyFile = Path.Combine(secretsDir, "session-signing.key");

        if (File.Exists(keyFile))
        {
            var existing = File.ReadAllText(keyFile).Trim();
            if (existing.Length >= 32)
                return existing;
        }

        var generated = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        File.WriteAllText(keyFile, generated);
        return generated;
    }
}

public static class StartupConfigurationValidator
{
    public static StartupValidationResult Validate(
        IConfiguration configuration,
        IHostEnvironment environment,
        RelayOptions relayOptions)
    {
        var warnings = new List<string>();
        var errors = new List<string>();

        var connStr = configuration.GetConnectionString("DefaultConnection")
            ?? Environment.GetEnvironmentVariable("REMOTEDESKTOP_DB");

        var useInMemoryForTesting = configuration.GetValue("Testing:UseInMemoryDatabase", false);
        if (!useInMemoryForTesting && string.IsNullOrWhiteSpace(connStr))
        {
            errors.Add(
                "PostgreSQL connection string is missing. Configure ConnectionStrings:DefaultConnection in server appsettings or REMOTEDESKTOP_DB on the server host.");
        }

        var allowOptionalTurn = environment.IsDevelopment()
            && configuration.GetValue("Development:AllowUnconfiguredTurnForNonMediaStages", true);

        if (!relayOptions.IsConfigured)
        {
            var missing = new List<string>();
            if (string.IsNullOrWhiteSpace(relayOptions.Host)) missing.Add("Relay:Host");
            if (string.IsNullOrWhiteSpace(relayOptions.Realm)) missing.Add("Relay:Realm");
            if (string.IsNullOrWhiteSpace(relayOptions.SharedSecret) || relayOptions.SharedSecret.Length < 32)
                missing.Add("Relay:SharedSecret (server-only, >=32 chars)");

            var message =
                $"TURN media relay is not configured ({string.Join(", ", missing)} missing). Control-plane operations remain available, while relayed media sessions will reject connection attempts until TURN is installed and configured.";

            if (allowOptionalTurn)
                warnings.Add(message);
            else
                errors.Add(message);
        }

        return new StartupValidationResult(errors.Count == 0, relayOptions.IsConfigured, warnings, errors);
    }

    public static ConfigValidationDto ToDto(
        string environmentName,
        bool adminConfigured,
        RelayOptions effectiveRelay,
        bool allowOptionalTurn)
    {
        var warnings = new List<string>();
        var errors = new List<string>();

        if (!adminConfigured)
        {
            warnings.Add("Administrator account has not been claimed yet. Complete first-run setup.");
        }

        if (!effectiveRelay.IsConfigured)
        {
            var missing = new List<string>();
            if (string.IsNullOrWhiteSpace(effectiveRelay.Host)) missing.Add("Relay Host");
            if (string.IsNullOrWhiteSpace(effectiveRelay.Realm)) missing.Add("TURN Realm");
            if (string.IsNullOrWhiteSpace(effectiveRelay.SharedSecret) || effectiveRelay.SharedSecret.Length < 32)
                missing.Add("Server-only TURN Shared Secret");

            var msg = $"TURN media relay is not configured ({string.Join(", ", missing)} missing). Media relay connections are blocked until configured.";
            if (allowOptionalTurn)
                warnings.Add(msg);
            else
                errors.Add(msg);
        }

        return new ConfigValidationDto(
            Environment: environmentName,
            Valid: errors.Count == 0,
            AdminConfigured: adminConfigured,
            SessionSecretProvisioned: true,
            TurnConfigured: effectiveRelay.IsConfigured,
            TurnStatus: effectiveRelay.IsConfigured ? "Configured" : "NotConfigured",
            Warnings: warnings,
            Errors: errors);
    }
}

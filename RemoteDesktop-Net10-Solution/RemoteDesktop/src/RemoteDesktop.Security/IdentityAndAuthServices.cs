using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Sessions;

namespace RemoteDesktop.Security;

public sealed class SecurityOptions
{
    public string JwtIssuer { get; set; } = "RemoteDesktop.ControlPlane";
    public string JwtAudience { get; set; } = "RemoteDesktop.Clients";
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(4);
    public TimeSpan DeviceTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public bool RequireDeviceApproval { get; set; } = true;
    public bool RequireMfaForSensitiveOperations { get; set; } = true;
}

public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string storedHash);
}

public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private const int Iterations = 210_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public string HashPassword(string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool VerifyPassword(string password, string storedHash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(storedHash))
            return false;

        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256")
            return false;

        if (!int.TryParse(parts[1], out var iterations) || iterations < 10_000)
            return false;

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expectedHash = Convert.FromBase64String(parts[3]);
            var actualHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expectedHash.Length);
            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        catch
        {
            return false;
        }
    }
}

public interface ITokenService
{
    (string Token, DateTimeOffset ExpiresAt, string Jti) IssueUserToken(Guid userId, string email, string role);
    (string Token, DateTimeOffset ExpiresAt, string Jti) IssueDeviceToken(Guid deviceId, string displayName, string fingerprint);
    TokenValidationParameters CreateValidationParameters();
}

public sealed class JwtTokenService : ITokenService
{
    private readonly SecurityOptions _options;
    private readonly SymmetricSecurityKey _signingKey;

    public JwtTokenService(SecurityOptions options, string rawSigningKey)
    {
        if (string.IsNullOrWhiteSpace(rawSigningKey) || rawSigningKey.Length < 32)
            throw new InvalidOperationException("Server JWT signing key must be at least 32 characters.");

        _options = options;
        var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawSigningKey));
        _signingKey = new SymmetricSecurityKey(keyBytes);
    }

    public (string Token, DateTimeOffset ExpiresAt, string Jti) IssueUserToken(Guid userId, string email, string role)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.Add(_options.AccessTokenLifetime);
        var jti = Guid.NewGuid().ToString("N");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(JwtRegisteredClaimNames.Email, email),
            new(ClaimTypes.Email, email),
            new(ClaimTypes.Role, role),
            new("participant_type", "user"),
            new(JwtRegisteredClaimNames.Jti, jti)
        };

        return WriteToken(claims, now, expiresAt, jti);
    }

    public (string Token, DateTimeOffset ExpiresAt, string Jti) IssueDeviceToken(Guid deviceId, string displayName, string fingerprint)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.Add(_options.DeviceTokenLifetime);
        var jti = Guid.NewGuid().ToString("N");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, deviceId.ToString()),
            new("device_id", deviceId.ToString()),
            new("device_name", displayName),
            new("device_fingerprint", fingerprint),
            new(ClaimTypes.Role, "HostDevice"),
            new("participant_type", "device"),
            new(JwtRegisteredClaimNames.Jti, jti)
        };

        return WriteToken(claims, now, expiresAt, jti);
    }

    public TokenValidationParameters CreateValidationParameters() => new()
    {
        ValidateIssuer = true,
        ValidIssuer = _options.JwtIssuer,
        ValidateAudience = true,
        ValidAudience = _options.JwtAudience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = _signingKey,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30),
        RoleClaimType = ClaimTypes.Role,
        NameClaimType = ClaimTypes.NameIdentifier
    };

    private (string Token, DateTimeOffset ExpiresAt, string Jti) WriteToken(
        IEnumerable<Claim> claims,
        DateTimeOffset now,
        DateTimeOffset expiresAt,
        string jti)
    {
        var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _options.JwtIssuer,
            audience: _options.JwtAudience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: creds);

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAt, jti);
    }
}

public interface IDeviceIdentityService
{
    (string PublicKeyBase64, byte[] ProtectedPrivateKey, string Fingerprint) CreateDeviceKeyPair();
    byte[] SignChallenge(byte[] protectedPrivateKey, byte[] challengeNonce);
    bool VerifyChallengeSignature(string publicKeyBase64, byte[] challengeNonce, byte[] signature);
    string ComputeFingerprint(string publicKeyBase64);
}

public sealed class DeviceIdentityService : IDeviceIdentityService
{
    public (string PublicKeyBase64, byte[] ProtectedPrivateKey, string Fingerprint) CreateDeviceKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var privateKey = ecdsa.ExportPkcs8PrivateKey();

        var protectedKey = OperatingSystem.IsWindows()
            ? ProtectedData.Protect(privateKey, null, DataProtectionScope.LocalMachine)
            : privateKey;

        Array.Clear(privateKey, 0, privateKey.Length);
        var publicBase64 = Convert.ToBase64String(publicKey);
        return (publicBase64, protectedKey, ComputeFingerprint(publicBase64));
    }

    public byte[] SignChallenge(byte[] protectedPrivateKey, byte[] challengeNonce)
    {
        var privateKey = OperatingSystem.IsWindows()
            ? ProtectedData.Unprotect(protectedPrivateKey, null, DataProtectionScope.LocalMachine)
            : protectedPrivateKey;

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(privateKey, out _);
            return ecdsa.SignData(challengeNonce, HashAlgorithmName.SHA256);
        }
        finally
        {
            if (OperatingSystem.IsWindows())
            {
                Array.Clear(privateKey, 0, privateKey.Length);
            }
        }
    }

    public bool VerifyChallengeSignature(string publicKeyBase64, byte[] challengeNonce, byte[] signature)
    {
        try
        {
            var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return ecdsa.VerifyData(challengeNonce, signature, HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }

    public string ComputeFingerprint(string publicKeyBase64)
    {
        var bytes = Convert.FromBase64String(publicKeyBase64);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash[..16]).ToLowerInvariant();
    }
}

public interface ISessionAuthorisationService
{
    bool CanInitiateSession(
        bool deviceApproved,
        bool deviceRevoked,
        bool unattendedRequested,
        bool deviceUnattendedAllowed,
        bool userUnattendedAllowed,
        DevicePermission grantedPermissions,
        bool callerIsAdmin);
}

public sealed class SessionAuthorisationService : ISessionAuthorisationService
{
    public bool CanInitiateSession(
        bool deviceApproved,
        bool deviceRevoked,
        bool unattendedRequested,
        bool deviceUnattendedAllowed,
        bool userUnattendedAllowed,
        DevicePermission grantedPermissions,
        bool callerIsAdmin)
    {
        if (!deviceApproved || deviceRevoked)
            return false;

        if (!callerIsAdmin && !grantedPermissions.HasFlag(DevicePermission.ViewScreen))
            return false;

        if (unattendedRequested && (!deviceUnattendedAllowed || (!callerIsAdmin && !userUnattendedAllowed)))
            return false;

        return true;
    }
}

public interface ITurnCredentialProvider
{
    bool IsConfigured { get; }
    TurnCredentialsDto GenerateEphemeralCredentials(Guid sessionId, TimeSpan ttl);
}

public sealed class TurnCredentialProvider : ITurnCredentialProvider
{
    private readonly string _sharedSecret;
    private readonly IReadOnlyList<string> _turnUrls;

    public TurnCredentialProvider(string sharedSecret, IReadOnlyList<string> turnUrls)
    {
        _sharedSecret = sharedSecret ?? string.Empty;
        _turnUrls = turnUrls;
    }

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(_sharedSecret)
        && _sharedSecret.Length >= 32
        && _turnUrls.Count > 0
        && _turnUrls.All(u => u.StartsWith("turn:", StringComparison.OrdinalIgnoreCase) || u.StartsWith("turns:", StringComparison.OrdinalIgnoreCase));

    public TurnCredentialsDto GenerateEphemeralCredentials(Guid sessionId, TimeSpan ttl)
    {
        if (!IsConfigured)
        {
            throw new InvalidOperationException(
                "TURN relay is not configured on the backend. Server-only TURN_SHARED_SECRET (>=32 chars) and relay URI are required before issuing relay credentials.");
        }

        var expiresAt = DateTimeOffset.UtcNow.Add(ttl);
        var unixExpiry = expiresAt.ToUnixTimeSeconds();
        var username = $"{unixExpiry}:{sessionId:N}";

        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(_sharedSecret));
        var digest = hmac.ComputeHash(Encoding.UTF8.GetBytes(username));
        var credential = Convert.ToBase64String(digest);

        return new TurnCredentialsDto(_turnUrls, username, credential, expiresAt, RelayOnly: true, IceTransportPolicy: "relay");
    }
}

using System.Security.Cryptography;

namespace RhodiumVaultServer;

public sealed class ServerOptions
{
    public string DataDir { get; set; } = Path.Combine(AppContext.BaseDirectory, "data");
    /// <summary>Set to true when running behind a reverse proxy that sets X-Forwarded-For / X-Forwarded-Proto.</summary>
    public bool TrustProxy { get; set; }
    /// <summary>Only for local testing on a non-localhost http address. WebCrypto needs https or localhost anyway.</summary>
    public bool AllowInsecureHttp { get; set; }
    public int MaxHistory { get; set; } = 20;
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(30);
    public TimeSpan SessionAbsoluteLifetime { get; set; } = TimeSpan.FromHours(12);
}

/// <summary>Server-side hashing of the browser-derived auth key (defence in depth: the DB never holds the auth key itself).</summary>
public static class AuthHasher
{
    private const int Iterations = 100_000;

    public static (byte[] Hash, byte[] Salt) Hash(byte[] authKey)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        return (Rfc2898DeriveBytes.Pbkdf2(authKey, salt, Iterations, HashAlgorithmName.SHA256, 32), salt);
    }

    public static bool Verify(byte[] authKey, byte[] salt, byte[] expectedHash)
    {
        var actual = Rfc2898DeriveBytes.Pbkdf2(authKey, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }

    /// <summary>Burns comparable CPU time when no real comparison happens, so failure paths don't reveal themselves by timing.</summary>
    public static void BurnTime() => Rfc2898DeriveBytes.Pbkdf2(new byte[32], new byte[16], Iterations, HashAlgorithmName.SHA256, 32);
}

/// <summary>
/// Brute-force protection for everything that verifies a secret (login, setup token, current password on change).
/// Per client IP: after 5 failures, exponentially growing lockout (15 s, 30 s, ... capped at 15 min).
/// Globally: too many failures in a short window pause all attempts, which also blunts distributed guessing.
/// </summary>
public sealed class LoginThrottle
{
    private const int FreeAttempts = 5;
    private const int GlobalLimit = 60;
    private static readonly TimeSpan GlobalWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ForgetAfter = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan MaxLock = TimeSpan.FromMinutes(15);

    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, (int Fails, DateTime LockedUntil, DateTime LastFail)> _byIp = new();
    private readonly Queue<DateTime> _global = new();

    public LoginThrottle(TimeProvider time) => _time = time;

    /// <summary>Returns null if an attempt is allowed, otherwise how long the caller must wait.</summary>
    public TimeSpan? CheckBlocked(string client)
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow().UtcDateTime;
            while (_global.Count > 0 && now - _global.Peek() > GlobalWindow) _global.Dequeue();

            if (_global.Count >= GlobalLimit)
            {
                var wait = _global.Peek() + GlobalWindow - now;
                return wait > TimeSpan.Zero ? wait : TimeSpan.FromSeconds(1);
            }
            if (_byIp.TryGetValue(client, out var s) && s.LockedUntil > now) return s.LockedUntil - now;
            return null;
        }
    }

    public void RecordFailure(string client)
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow().UtcDateTime;
            _global.Enqueue(now);

            if (_byIp.Count > 10_000) _byIp.Clear(); // bounded memory under a spoofing flood
            _byIp.TryGetValue(client, out var s);
            var fails = (s.Fails > 0 && now - s.LastFail < ForgetAfter) ? s.Fails + 1 : 1;

            var lockedUntil = DateTime.MinValue;
            if (fails >= FreeAttempts)
            {
                var seconds = Math.Min(MaxLock.TotalSeconds, 15 * Math.Pow(2, fails - FreeAttempts));
                lockedUntil = now.AddSeconds(seconds);
            }
            _byIp[client] = (fails, lockedUntil, now);
        }
    }

    public void RecordSuccess(string client)
    {
        lock (_gate) { _byIp.Remove(client); }
    }
}

/// <summary>One-time secret printed to the server log on first start so only the operator can create the account.</summary>
public sealed class SetupToken
{
    private byte[] _hash = Array.Empty<byte>();
    public string? Current { get; private set; }

    public void Generate()
    {
        Current = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', 'A').Replace('/', 'B').TrimEnd('=');
        _hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Current));
    }

    public bool Matches(string? candidate)
    {
        if (Current == null || string.IsNullOrEmpty(candidate)) return false;
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(candidate)), _hash);
    }

    public void Clear() { Current = null; _hash = Array.Empty<byte>(); }
}

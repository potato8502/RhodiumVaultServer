using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.HttpOverrides;
using RhodiumVaultServer;

const string CookieName = "rvs_session";
const string Version = "0.1.0";

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = "wwwroot",
});

// Configuration: environment variables RVS_DATADIR, RVS_TRUSTPROXY, RVS_ALLOWINSECUREHTTP (or the same keys without prefix in config).
builder.Configuration.AddEnvironmentVariables(prefix: "RVS_");

builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 3_000_000);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<IConfiguration>();
    return new ServerOptions
    {
        DataDir = cfg["DataDir"] ?? Path.Combine(AppContext.BaseDirectory, "data"),
        TrustProxy = cfg.GetValue("TrustProxy", false),
        AllowInsecureHttp = cfg.GetValue("AllowInsecureHttp", false),
        MaxHistory = cfg.GetValue("MaxHistory", 20),
        SessionIdleTimeout = TimeSpan.FromMinutes(cfg.GetValue("SessionIdleMinutes", 30)),
        SessionAbsoluteLifetime = TimeSpan.FromHours(cfg.GetValue("SessionAbsoluteHours", 12)),
    };
});
builder.Services.AddSingleton(sp =>
{
    var o = sp.GetRequiredService<ServerOptions>();
    return new VaultStore(o.DataDir, sp.GetRequiredService<TimeProvider>(), o.MaxHistory);
});
builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddSingleton<SetupToken>();

if (builder.Configuration.GetValue("TrustProxy", false))
{
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
        o.KnownIPNetworks.Clear(); // the reverse proxy is trusted by operator decision (RVS_TRUSTPROXY=true)
        o.KnownProxies.Clear();
    });
}

var app = builder.Build();
var log = app.Logger;
var options = app.Services.GetRequiredService<ServerOptions>();
var store = app.Services.GetRequiredService<VaultStore>();
var throttle = app.Services.GetRequiredService<LoginThrottle>();
var setupToken = app.Services.GetRequiredService<SetupToken>();
var time = app.Services.GetRequiredService<TimeProvider>();

if (options.TrustProxy) app.UseForwardedHeaders();

if (!store.HasAccount())
{
    setupToken.Generate();
    log.LogWarning("==================================================================");
    log.LogWarning(" FIRST START - no account yet. Setup token (needed once, in the browser):");
    log.LogWarning("   {Token}", setupToken.Current);
    log.LogWarning(" This token changes on every restart until the account is created.");
    log.LogWarning("==================================================================");
}

// ---------- helpers ----------

static bool IsLocalHost(string host) => host is "localhost" or "127.0.0.1" or "::1" or "[::1]";
bool TransportOk(HttpContext c) => c.Request.IsHttps || options.AllowInsecureHttp || IsLocalHost(c.Request.Host.Host);
static string ClientOf(HttpContext c) => c.Connection.RemoteIpAddress?.ToString() ?? "unknown";
static byte[] TokenHash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));
static IResult Err(int status, string code) => Results.Json(new { error = code }, statusCode: status);

IResult TooManyRequests(HttpContext c, TimeSpan wait)
{
    c.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
    return Err(StatusCodes.Status429TooManyRequests, "too-many-attempts");
}

void IssueSession(HttpContext c)
{
    var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    store.CreateSession(TokenHash(token), options.SessionAbsoluteLifetime);
    c.Response.Cookies.Append(CookieName, token, new CookieOptions
    {
        HttpOnly = true,
        Secure = c.Request.IsHttps,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        IsEssential = true,
    });
}

static object BlobOf(string json) => System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(json);

// ---------- security headers on every response ----------

app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        var h = ctx.Response.Headers;
        h["Content-Security-Policy"] = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";
        h["X-Content-Type-Options"] = "nosniff";
        h["Referrer-Policy"] = "no-referrer";
        h["X-Frame-Options"] = "DENY";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
        h["Cross-Origin-Opener-Policy"] = "same-origin";
        h["Cross-Origin-Resource-Policy"] = "same-origin";
        if (ctx.Request.IsHttps) h["Strict-Transport-Security"] = "max-age=31536000";
        h["Cache-Control"] = ctx.Request.Path.StartsWithSegments("/api") ? "no-store" : "no-cache";
        return Task.CompletedTask;
    });
    await next();
});

// ---------- CSRF defence for state-changing API calls: custom header + same-origin check ----------

app.Use(async (ctx, next) =>
{
    var m = ctx.Request.Method;
    var unsafeMethod = !(HttpMethods.IsGet(m) || HttpMethods.IsHead(m) || HttpMethods.IsOptions(m));
    if (unsafeMethod && ctx.Request.Path.StartsWithSegments("/api"))
    {
        var headerOk = ctx.Request.Headers["X-RVS-Request"] == "1";
        var origin = ctx.Request.Headers.Origin.ToString();
        var originOk = string.IsNullOrEmpty(origin)
            || (Uri.TryCreate(origin, UriKind.Absolute, out var u)
                && string.Equals(u.Authority, ctx.Request.Host.Value, StringComparison.OrdinalIgnoreCase));
        if (!headerOk || !originOk)
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { error = "csrf-check-failed" });
            return;
        }
    }
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

// ---------- API ----------

var api = app.MapGroup("/api");

api.MapGet("/status", (HttpContext c) => Results.Json(new
{
    setupRequired = !store.HasAccount(),
    version = Version,
    secureContext = TransportOk(c),
}));

api.MapPost("/setup", (SetupRequest req, HttpContext c) =>
{
    if (!TransportOk(c)) return Err(400, "https-required");
    if (store.HasAccount()) return Err(409, "already-setup");

    var client = ClientOf(c);
    if (throttle.CheckBlocked(client) is { } wait) return TooManyRequests(c, wait);

    var authKey = Base64.TryDecode(req.AuthKey, 32);
    var salt = Base64.TryDecode(req.Salt, 16);
    if (authKey == null || salt == null || req.Kdf is not { IsSane: true } || req.Blob is not { IsValid: true })
        return Err(400, "invalid-request");

    if (!setupToken.Matches(req.SetupToken))
    {
        AuthHasher.BurnTime();
        throttle.RecordFailure(client);
        log.LogWarning("setup-failed reason=bad-token ip={Ip}", client);
        return Err(403, "bad-setup-token");
    }

    var (hash, hashSalt) = AuthHasher.Hash(authKey);
    if (!store.CreateAccount(salt, req.Kdf, hash, hashSalt, req.Blob.ToJson())) return Err(409, "already-setup");

    setupToken.Clear();
    throttle.RecordSuccess(client);
    IssueSession(c);
    log.LogInformation("setup-complete ip={Ip}", client);
    return Results.Json(new { revision = 1 });
});

api.MapGet("/prelogin", () =>
{
    var acct = store.GetAccount();
    if (acct == null) return Err(409, "setup-required");
    return Results.Json(new { salt = Convert.ToBase64String(acct.Salt), kdf = acct.Kdf });
});

api.MapPost("/login", (LoginRequest req, HttpContext c) =>
{
    if (!TransportOk(c)) return Err(400, "https-required");
    var client = ClientOf(c);
    if (throttle.CheckBlocked(client) is { } wait) return TooManyRequests(c, wait);

    var authKey = Base64.TryDecode(req.AuthKey, 32);
    if (authKey == null) return Err(400, "invalid-request");

    var acct = store.GetAccount();
    if (acct == null) return Err(409, "setup-required");

    if (!AuthHasher.Verify(authKey, acct.AuthHashSalt, acct.AuthHash))
    {
        throttle.RecordFailure(client);
        log.LogWarning("login-failed ip={Ip}", client);
        return Err(401, "invalid-credentials");
    }

    throttle.RecordSuccess(client);
    IssueSession(c);
    log.LogInformation("login-ok ip={Ip}", client);
    return Results.Json(new { revision = store.GetVault()?.Revision ?? 0 });
});

api.MapPost("/logout", (HttpContext c) =>
{
    if (c.Request.Cookies.TryGetValue(CookieName, out var token) && !string.IsNullOrEmpty(token))
        store.DeleteSession(TokenHash(token));
    c.Response.Cookies.Delete(CookieName, new CookieOptions { Path = "/", HttpOnly = true, Secure = c.Request.IsHttps, SameSite = SameSiteMode.Strict });
    return Results.NoContent();
});

// ----- everything below requires a valid session -----

var authed = api.MapGroup("").AddEndpointFilter(async (ctx, next) =>
{
    var http = ctx.HttpContext;
    if (!http.Request.Cookies.TryGetValue(CookieName, out var token) || string.IsNullOrEmpty(token)
        || !store.ValidateAndTouchSession(TokenHash(token), options.SessionIdleTimeout))
        return Err(401, "unauthorized");
    return await next(ctx);
});

authed.MapGet("/vault", () =>
{
    var acct = store.GetAccount();
    var v = store.GetVault();
    if (acct == null || v == null) return Err(409, "setup-required");
    return Results.Json(new
    {
        revision = v.Revision,
        blob = BlobOf(v.BlobJson),
        salt = Convert.ToBase64String(acct.Salt),
        kdf = acct.Kdf,
        updatedUtc = v.UpdatedUtc,
    });
});

authed.MapPut("/vault", (PutVaultRequest req) =>
{
    if (req.Blob is not { IsValid: true }) return Err(400, "invalid-request");
    var next = store.PutVault(req.ExpectedRevision, req.Blob.ToJson());
    if (next == null)
        return Results.Json(new { error = "conflict", currentRevision = store.GetVault()?.Revision ?? 0 }, statusCode: 409);
    return Results.Json(new { revision = next.Value });
});

authed.MapPost("/change-password", (ChangePasswordRequest req, HttpContext c) =>
{
    var client = ClientOf(c);
    if (throttle.CheckBlocked(client) is { } wait) return TooManyRequests(c, wait);

    var current = Base64.TryDecode(req.CurrentAuthKey, 32);
    var next = Base64.TryDecode(req.NewAuthKey, 32);
    var salt = Base64.TryDecode(req.Salt, 16);
    if (current == null || next == null || salt == null || req.Kdf is not { IsSane: true } || req.Blob is not { IsValid: true })
        return Err(400, "invalid-request");

    var acct = store.GetAccount();
    if (acct == null) return Err(409, "setup-required");
    if (!AuthHasher.Verify(current, acct.AuthHashSalt, acct.AuthHash))
    {
        throttle.RecordFailure(client);
        log.LogWarning("change-password-failed reason=wrong-current ip={Ip}", client);
        return Err(401, "invalid-credentials");
    }

    var (newHash, newHashSalt) = AuthHasher.Hash(next);
    var rev = store.ChangePassword(req.ExpectedRevision, acct.AuthHash, salt, req.Kdf, newHash, newHashSalt, req.Blob.ToJson());
    if (rev == null)
        return Results.Json(new { error = "conflict", currentRevision = store.GetVault()?.Revision ?? 0 }, statusCode: 409);

    throttle.RecordSuccess(client);
    IssueSession(c); // all old sessions were invalidated by the change
    log.LogInformation("change-password-ok ip={Ip}", client);
    return Results.Json(new { revision = rev.Value });
});

authed.MapGet("/history", () => Results.Json(store.ListHistory().Select(h => new { revision = h.Revision, createdUtc = h.CreatedUtc })));

authed.MapGet("/history/{revision:long}", (long revision) =>
{
    var h = store.GetHistory(revision);
    if (h == null) return Err(404, "not-found");
    return Results.Json(new
    {
        revision = h.Revision,
        blob = BlobOf(h.BlobJson),
        salt = Convert.ToBase64String(h.Salt),
        kdf = h.Kdf,
        createdUtc = h.CreatedUtc,
    });
});

// Encrypted backup file: can be used on a fresh server via "restore from backup" in the setup screen.
authed.MapGet("/backup", (HttpContext c) =>
{
    var acct = store.GetAccount();
    var v = store.GetVault();
    if (acct == null || v == null) return Err(409, "setup-required");
    c.Response.Headers.ContentDisposition = $"attachment; filename=\"rhodium-vault-backup-{time.GetUtcNow():yyyyMMdd-HHmm}.json\"";
    return Results.Json(new
    {
        format = "rhodium-vault-server-backup",
        formatVersion = 1,
        exportedUtc = time.GetUtcNow(),
        revision = v.Revision,
        salt = Convert.ToBase64String(acct.Salt),
        kdf = acct.Kdf,
        blob = BlobOf(v.BlobJson),
    });
});

app.Run();

public partial class Program { }

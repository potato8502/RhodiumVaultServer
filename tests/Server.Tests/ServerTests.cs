using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using RhodiumVaultServer;
using Xunit;

namespace Server.Tests;

public sealed class TestApp : WebApplicationFactory<Program>
{
    public string DataDir { get; } = Path.Combine(Path.GetTempPath(), "rvs-tests-" + Guid.NewGuid().ToString("N"));
    public FakeTimeProvider Time { get; } = new(new DateTimeOffset(2026, 9, 25, 12, 0, 0, TimeSpan.Zero));

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.UseSetting("DataDir", DataDir);
        builder.ConfigureServices(s => { s.RemoveAll<TimeProvider>(); s.AddSingleton<TimeProvider>(Time); });
    }

    public string SetupTokenValue => Services.GetRequiredService<SetupToken>().Current!;

    public HttpClient Client(string baseAddress = "https://localhost", bool cookies = true)
    {
        var c = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri(baseAddress), HandleCookies = cookies, AllowAutoRedirect = false });
        c.DefaultRequestHeaders.Add("X-RVS-Request", "1");
        return c;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { Directory.Delete(DataDir, true); } catch { /* best effort */ }
    }
}

public class ServerTests : IDisposable
{
    private readonly TestApp _app = new();
    public void Dispose() => _app.Dispose();

    // ---- helpers: what the browser would send. The server only checks shapes, never plaintext. ----

    private static string B64(byte[] b) => Convert.ToBase64String(b);
    private static byte[] Rnd(int n) => RandomNumberGenerator.GetBytes(n);

    private static object Blob(int ctLen = 48) => new { v = 1, nonce = B64(Rnd(12)), ciphertext = B64(Rnd(ctLen)) };
    private static readonly object Kdf = new { memoryKiB = 8192, iterations = 1, parallelism = 1 };

    private record Creds(byte[] AuthKey, byte[] Salt)
    {
        public static Creds New() => new(Rnd(32), Rnd(16));
    }

    private object SetupBody(Creds c, string? token = null, object? blob = null) =>
        new { setupToken = token ?? _app.SetupTokenValue, authKey = B64(c.AuthKey), salt = B64(c.Salt), kdf = Kdf, blob = blob ?? Blob() };

    private async Task<HttpClient> SetupAndLogin(Creds c)
    {
        var client = _app.Client();
        var r = await client.PostAsJsonAsync("/api/setup", SetupBody(c));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return client;
    }

    private async Task<HttpClient> Login(Creds c)
    {
        var client = _app.Client();
        var r = await client.PostAsJsonAsync("/api/login", new { authKey = B64(c.AuthKey) });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return client;
    }

    private static async Task<JsonElement> Json(HttpResponseMessage r) => JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement.Clone();

    // ---------------- setup ----------------

    [Fact]
    public async Task Status_reports_setup_required_until_an_account_exists()
    {
        var client = _app.Client();
        Assert.True((await Json(await client.GetAsync("/api/status"))).GetProperty("setupRequired").GetBoolean());
        await SetupAndLogin(Creds.New());
        Assert.False((await Json(await client.GetAsync("/api/status"))).GetProperty("setupRequired").GetBoolean());
    }

    [Fact]
    public async Task Setup_needs_the_token_from_the_server_log()
    {
        var c = Creds.New();
        var client = _app.Client();
        var bad = await client.PostAsJsonAsync("/api/setup", SetupBody(c, token: "not-the-token"));
        Assert.Equal(HttpStatusCode.Forbidden, bad.StatusCode);
        Assert.False(_app.Services.GetRequiredService<VaultStore>().HasAccount());

        var good = await client.PostAsJsonAsync("/api/setup", SetupBody(c));
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
    }

    [Fact]
    public async Task Setup_can_only_happen_once()
    {
        await SetupAndLogin(Creds.New());
        var again = await _app.Client().PostAsJsonAsync("/api/setup", SetupBody(Creds.New(), token: "anything"));
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }

    [Fact]
    public async Task Setup_sets_a_hardened_session_cookie()
    {
        var r = await _app.Client(cookies: false).PostAsJsonAsync("/api/setup", SetupBody(Creds.New()));
        var cookie = r.Headers.GetValues("Set-Cookie").Single(h => h.StartsWith("rvs_session="));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Malformed_setup_requests_are_rejected()
    {
        var c = Creds.New();
        var client = _app.Client();
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/setup", new { setupToken = _app.SetupTokenValue, authKey = B64(Rnd(5)), salt = B64(c.Salt), kdf = Kdf, blob = Blob() })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/setup", new { setupToken = _app.SetupTokenValue, authKey = B64(c.AuthKey), salt = B64(Rnd(3)), kdf = Kdf, blob = Blob() })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/setup", new { setupToken = _app.SetupTokenValue, authKey = B64(c.AuthKey), salt = B64(c.Salt), kdf = new { memoryKiB = 1, iterations = 1, parallelism = 1 }, blob = Blob() })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/setup", new { setupToken = _app.SetupTokenValue, authKey = B64(c.AuthKey), salt = B64(c.Salt), kdf = Kdf, blob = new { v = 2, nonce = B64(Rnd(12)), ciphertext = B64(Rnd(48)) } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/setup", new { setupToken = _app.SetupTokenValue, authKey = B64(c.AuthKey), salt = B64(c.Salt), kdf = Kdf, blob = new { v = 1, nonce = B64(Rnd(12)), ciphertext = new string('A', BlobDto.MaxCiphertextBase64 + 4) } })).StatusCode);
        Assert.False(_app.Services.GetRequiredService<VaultStore>().HasAccount());
    }

    [Fact]
    public async Task Https_or_localhost_is_required()
    {
        var r = await _app.Client("http://vault.example").PostAsJsonAsync("/api/setup", SetupBody(Creds.New()));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Equal("https-required", (await Json(r)).GetProperty("error").GetString());

        var local = await _app.Client("http://localhost").PostAsJsonAsync("/api/setup", SetupBody(Creds.New()));
        Assert.Equal(HttpStatusCode.OK, local.StatusCode);
    }

    // ---------------- CSRF ----------------

    [Fact]
    public async Task State_changing_requests_need_the_custom_header_and_a_same_origin_origin()
    {
        var noHeader = _app.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        Assert.Equal(HttpStatusCode.Forbidden, (await noHeader.PostAsJsonAsync("/api/setup", SetupBody(Creds.New()))).StatusCode);

        var evil = _app.Client();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/setup") { Content = JsonContent.Create(SetupBody(Creds.New())) };
        req.Headers.Add("Origin", "https://evil.example");
        Assert.Equal(HttpStatusCode.Forbidden, (await evil.SendAsync(req)).StatusCode);

        var same = new HttpRequestMessage(HttpMethod.Post, "/api/setup") { Content = JsonContent.Create(SetupBody(Creds.New())) };
        same.Headers.Add("Origin", "https://localhost");
        Assert.Equal(HttpStatusCode.OK, (await _app.Client().SendAsync(same)).StatusCode);
    }

    // ---------------- login / sessions ----------------

    [Fact]
    public async Task Prelogin_returns_public_salt_and_kdf_only_after_setup()
    {
        var client = _app.Client();
        Assert.Equal(HttpStatusCode.Conflict, (await client.GetAsync("/api/prelogin")).StatusCode);

        var c = Creds.New();
        await SetupAndLogin(c);
        var pre = await Json(await client.GetAsync("/api/prelogin"));
        Assert.Equal(B64(c.Salt), pre.GetProperty("salt").GetString());
        Assert.Equal(8192, pre.GetProperty("kdf").GetProperty("memoryKiB").GetInt32());
    }

    [Fact]
    public async Task Login_rejects_wrong_credentials_and_vault_needs_a_session()
    {
        var c = Creds.New();
        await SetupAndLogin(c);

        var anon = _app.Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/api/vault")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/api/login", new { authKey = B64(Rnd(32)) })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/api/vault")).StatusCode);

        var ok = await Login(c);
        Assert.Equal(HttpStatusCode.OK, (await ok.GetAsync("/api/vault")).StatusCode);
    }

    [Fact]
    public async Task Repeated_failures_lock_the_client_out_even_for_the_right_password_then_recover()
    {
        var c = Creds.New();
        await SetupAndLogin(c);
        var client = _app.Client();

        for (int i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/login", new { authKey = B64(Rnd(32)) })).StatusCode);

        var locked = await client.PostAsJsonAsync("/api/login", new { authKey = B64(c.AuthKey) });
        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
        Assert.True(locked.Headers.Contains("Retry-After"));

        _app.Time.Advance(TimeSpan.FromSeconds(20));
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/login", new { authKey = B64(c.AuthKey) })).StatusCode);
    }

    [Fact]
    public async Task Lockout_grows_with_more_failures()
    {
        var c = Creds.New();
        await SetupAndLogin(c);
        var client = _app.Client();
        for (int i = 0; i < 5; i++) await client.PostAsJsonAsync("/api/login", new { authKey = B64(Rnd(32)) });
        _app.Time.Advance(TimeSpan.FromSeconds(16));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/login", new { authKey = B64(Rnd(32)) })).StatusCode); // 6th failure -> 30 s
        _app.Time.Advance(TimeSpan.FromSeconds(16));
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsJsonAsync("/api/login", new { authKey = B64(c.AuthKey) })).StatusCode);
        _app.Time.Advance(TimeSpan.FromSeconds(20));
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/login", new { authKey = B64(c.AuthKey) })).StatusCode);
    }

    [Fact]
    public async Task Sessions_expire_when_idle_and_after_the_absolute_lifetime()
    {
        var c = Creds.New();
        var client = await SetupAndLogin(c);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/vault")).StatusCode);

        _app.Time.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/vault")).StatusCode);

        var active = await Login(c);
        for (int i = 0; i < 36; i++) // stays active every 20 minutes for 12 hours
        {
            _app.Time.Advance(TimeSpan.FromMinutes(20));
            var status = (await active.GetAsync("/api/vault")).StatusCode;
            if (i < 35) Assert.Equal(HttpStatusCode.OK, status); else Assert.Equal(HttpStatusCode.Unauthorized, status);
        }
    }

    [Fact]
    public async Task Logout_invalidates_the_session_even_if_the_cookie_is_replayed()
    {
        var plain = _app.Client(cookies: false);
        var setup = await plain.PostAsJsonAsync("/api/setup", SetupBody(Creds.New()));
        var cookie = setup.Headers.GetValues("Set-Cookie").Single(h => h.StartsWith("rvs_session=")).Split(';')[0];

        HttpRequestMessage With(HttpMethod m, string url)
        {
            var req = new HttpRequestMessage(m, url);
            req.Headers.Add("Cookie", cookie);
            return req;
        }

        Assert.Equal(HttpStatusCode.OK, (await plain.SendAsync(With(HttpMethod.Get, "/api/vault"))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await plain.SendAsync(With(HttpMethod.Post, "/api/logout"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await plain.SendAsync(With(HttpMethod.Get, "/api/vault"))).StatusCode);
    }

    // ---------------- vault, revisions, history ----------------

    [Fact]
    public async Task Vault_saves_bump_the_revision_and_stale_saves_are_rejected_without_data_loss()
    {
        var c = Creds.New();
        var client = await SetupAndLogin(c);
        var b1 = Blob();
        var r1 = await Json(await client.PutAsJsonAsync("/api/vault", new { expectedRevision = 1, blob = b1 }));
        Assert.Equal(2, r1.GetProperty("revision").GetInt64());

        var stale = await client.PutAsJsonAsync("/api/vault", new { expectedRevision = 1, blob = Blob() });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Equal(2, (await Json(stale)).GetProperty("currentRevision").GetInt64());

        var current = await Json(await client.GetAsync("/api/vault"));
        Assert.Equal(2, current.GetProperty("revision").GetInt64());
        var stored = current.GetProperty("blob");
        Assert.Equal(((dynamic)b1).ciphertext, stored.GetProperty("ciphertext").GetString());
        Assert.Equal(((dynamic)b1).nonce, stored.GetProperty("nonce").GetString());
    }

    [Fact]
    public async Task Previous_versions_are_kept_in_history_and_history_is_pruned()
    {
        var client = await SetupAndLogin(Creds.New());
        for (long rev = 1; rev <= 25; rev++)
            Assert.Equal(HttpStatusCode.OK, (await client.PutAsJsonAsync("/api/vault", new { expectedRevision = rev, blob = Blob() })).StatusCode);

        var list = await Json(await client.GetAsync("/api/history"));
        var revisions = list.EnumerateArray().Select(e => e.GetProperty("revision").GetInt64()).ToList();
        Assert.Equal(20, revisions.Count);
        Assert.Equal(25, revisions.Max());
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/history/25")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/history/1")).StatusCode);
    }

    // ---------------- change password ----------------

    private object ChangeBody(Creds current, Creds next, long rev) => new
    {
        currentAuthKey = B64(current.AuthKey), newAuthKey = B64(next.AuthKey), salt = B64(next.Salt), kdf = Kdf, expectedRevision = rev, blob = Blob(),
    };

    [Fact]
    public async Task Changing_the_password_swaps_credentials_and_vault_and_kills_other_sessions()
    {
        var oldC = Creds.New();
        var other = await SetupAndLogin(oldC);      // session A
        var mine = await Login(oldC);               // session B

        var newC = Creds.New();
        var wrong = await mine.PostAsJsonAsync("/api/change-password", ChangeBody(Creds.New(), newC, 1));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        var ok = await mine.PostAsJsonAsync("/api/change-password", ChangeBody(oldC, newC, 1));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/api/vault")).StatusCode);       // old session gone
        Assert.Equal(HttpStatusCode.OK, (await mine.GetAsync("/api/vault")).StatusCode);                  // fresh session issued
        var fresh = _app.Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await fresh.PostAsJsonAsync("/api/login", new { authKey = B64(oldC.AuthKey) })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await fresh.PostAsJsonAsync("/api/login", new { authKey = B64(newC.AuthKey) })).StatusCode);
        Assert.Equal(B64(newC.Salt), (await Json(await fresh.GetAsync("/api/prelogin"))).GetProperty("salt").GetString());
    }

    [Fact]
    public async Task A_stale_password_change_is_rejected_and_leaves_the_old_credentials_intact()
    {
        var oldC = Creds.New();
        var client = await SetupAndLogin(oldC);
        await client.PutAsJsonAsync("/api/vault", new { expectedRevision = 1, blob = Blob() }); // now revision 2

        var newC = Creds.New();
        var r = await client.PostAsJsonAsync("/api/change-password", ChangeBody(oldC, newC, 1));
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);

        Assert.Equal(B64(oldC.Salt), (await Json(await _app.Client().GetAsync("/api/prelogin"))).GetProperty("salt").GetString());
        Assert.Equal(HttpStatusCode.OK, (await _app.Client().PostAsJsonAsync("/api/login", new { authKey = B64(oldC.AuthKey) })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _app.Client().PostAsJsonAsync("/api/login", new { authKey = B64(newC.AuthKey) })).StatusCode);
    }

    // ---------------- what is (not) stored ----------------

    [Fact]
    public async Task The_database_never_contains_the_auth_key_or_anything_but_the_submitted_ciphertext()
    {
        var c = Creds.New();
        var blob = Blob(64);
        var client = _app.Client();
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/setup", SetupBody(c, blob: blob))).StatusCode);
        await client.PostAsJsonAsync("/api/login", new { authKey = B64(c.AuthKey) });

        var bytes = new List<byte>();
        foreach (var f in Directory.GetFiles(_app.DataDir))
        {
            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var ms = new MemoryStream();
            fs.CopyTo(ms);
            bytes.AddRange(ms.ToArray());
        }
        var all = bytes.ToArray();

        Assert.True(IndexOf(all, c.AuthKey) < 0, "raw auth key found in the database files");
        Assert.True(IndexOf(all, Encoding.ASCII.GetBytes(B64(c.AuthKey))) < 0, "base64 auth key found in the database files");
        // The blob is stored as JSON text, where System.Text.Json escapes '+' as +.
        string ct = ((dynamic)blob).ciphertext;
        Assert.True(IndexOf(all, Encoding.ASCII.GetBytes(ct.Replace("+", "\\u002B"))) >= 0, "ciphertext should be stored as submitted");
    }

    private static int IndexOf(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle);

    // ---------------- headers, backup ----------------

    [Fact]
    public async Task Security_headers_are_present_on_api_responses_and_api_is_never_cached()
    {
        var r = await _app.Client().GetAsync("/api/status");
        var csp = r.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("script-src 'self' 'wasm-unsafe-eval'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Equal("nosniff", r.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", r.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("no-store", r.Headers.GetValues("Cache-Control").Single());
        Assert.True(r.Headers.Contains("Strict-Transport-Security")); // https base address
    }

    [Fact]
    public async Task Responses_expose_only_the_documented_fields()
    {
        var client = await SetupAndLogin(Creds.New());
        static string[] Keys(JsonElement e) => e.EnumerateObject().Select(p => p.Name).OrderBy(n => n).ToArray();

        var vault = await Json(await client.GetAsync("/api/vault"));
        Assert.Equal(new[] { "ciphertext", "nonce", "v" }, Keys(vault.GetProperty("blob")));
        Assert.Equal(new[] { "iterations", "memoryKiB", "parallelism" }, Keys(vault.GetProperty("kdf")));

        var pre = await Json(await _app.Client().GetAsync("/api/prelogin"));
        Assert.Equal(new[] { "iterations", "memoryKiB", "parallelism" }, Keys(pre.GetProperty("kdf")));

        var backup = await Json(await client.GetAsync("/api/backup"));
        Assert.Equal(new[] { "ciphertext", "nonce", "v" }, Keys(backup.GetProperty("blob")));
    }

    [Fact]
    public async Task The_web_ui_is_served_and_contains_no_inline_script_or_style_that_the_csp_would_block()
    {
        var page = await _app.Client().GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains("js/app.js", html);
        Assert.DoesNotMatch(@"<script(?![^>]*\bsrc=)[^>]*>", html);          // no inline <script>
        Assert.DoesNotMatch(@"<style\b", html);                              // no <style> blocks
        Assert.DoesNotMatch(@"\sstyle\s*=", html);                           // no style="" attributes
        Assert.DoesNotMatch(@"\son[a-z]+\s*=", html);                        // no onclick= handlers
        Assert.DoesNotMatch(@"https?://", html.Replace("http://www.w3.org/2000/svg", "")); // nothing loaded from other origins
        Assert.Equal(HttpStatusCode.OK, (await _app.Client().GetAsync("/js/crypto.js")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _app.Client().GetAsync("/js/vendor/argon2.umd.min.js")).StatusCode);
    }

    [Fact]
    public async Task Backup_is_an_authenticated_encrypted_export()
    {
        var c = Creds.New();
        var client = await SetupAndLogin(c);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _app.Client().GetAsync("/api/backup")).StatusCode);

        var backup = await client.GetAsync("/api/backup");
        Assert.Equal(HttpStatusCode.OK, backup.StatusCode);
        Assert.Contains("attachment", backup.Content.Headers.ContentDisposition?.ToString() ?? string.Join(",", backup.Headers.Select(h => h.Key)));
        var j = await Json(backup);
        Assert.Equal("rhodium-vault-server-backup", j.GetProperty("format").GetString());
        Assert.Equal(B64(c.Salt), j.GetProperty("salt").GetString());
        Assert.Equal(1, j.GetProperty("blob").GetProperty("v").GetInt32());
    }
}

/// <summary>Proves the browser (JS) and server-side (.NET) key derivation agree, using a vector produced by crypto.js.</summary>
public class CrossLanguageContractTests
{
    private record Vector(string Password, string SaltB64, JsonElement Kdf, string MasterKeyHex, string AuthKeyB64);

    private static Vector Load() =>
        JsonSerializer.Deserialize<Vector>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "argon2-vector.json")), JsonSerializerOptions.Web)!;

    [Fact]
    public void Konscious_Argon2id_reproduces_the_browser_master_key()
    {
        var v = Load();
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(v.Password.Normalize(NormalizationForm.FormKC)))
        {
            Salt = Convert.FromBase64String(v.SaltB64),
            MemorySize = v.Kdf.GetProperty("memoryKiB").GetInt32(),
            Iterations = v.Kdf.GetProperty("iterations").GetInt32(),
            DegreeOfParallelism = v.Kdf.GetProperty("parallelism").GetInt32(),
        };
        Assert.Equal(v.MasterKeyHex, Convert.ToHexString(argon.GetBytes(32)).ToLowerInvariant());
    }

    [Fact]
    public void Dotnet_HKDF_reproduces_the_browser_auth_key()
    {
        var v = Load();
        var master = Convert.FromHexString(v.MasterKeyHex);
        var auth = HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32, salt: new byte[32], info: Encoding.UTF8.GetBytes("rhodium-vault/auth/v1"));
        Assert.Equal(v.AuthKeyB64, Convert.ToBase64String(auth));
    }
}

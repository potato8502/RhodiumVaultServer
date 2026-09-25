using System.Text.Json;
using System.Text.Json.Serialization;

namespace RhodiumVaultServer;

public record KdfDto(int MemoryKiB, int Iterations, int Parallelism)
{
    [JsonIgnore]
    public bool IsSane =>
        MemoryKiB is >= 8192 and <= 1048576 && Iterations is >= 1 and <= 20 && Parallelism is >= 1 and <= 16;
}

/// <summary>An AES-256-GCM encrypted vault as produced by the browser. The server never looks inside.</summary>
public record BlobDto(int V, string Nonce, string Ciphertext)
{
    public const int MaxCiphertextBase64 = 2_000_000;

    [JsonIgnore]
    public bool IsValid =>
        V == 1
        && Base64.TryLength(Nonce, out var n) && n == 12
        && Ciphertext is { Length: > 0 } && Ciphertext.Length <= MaxCiphertextBase64
        && Base64.TryLength(Ciphertext, out var c) && c >= 16; // at least the GCM tag

    public string ToJson() => JsonSerializer.Serialize(this, JsonSerializerOptions.Web);
    public static BlobDto? FromJson(string json) => JsonSerializer.Deserialize<BlobDto>(json, JsonSerializerOptions.Web);
}

public record SetupRequest(string SetupToken, string AuthKey, string Salt, KdfDto Kdf, BlobDto Blob);
public record LoginRequest(string AuthKey);
public record PutVaultRequest(long ExpectedRevision, BlobDto Blob);
public record ChangePasswordRequest(string CurrentAuthKey, string NewAuthKey, string Salt, KdfDto Kdf, long ExpectedRevision, BlobDto Blob);

public record Account(byte[] Salt, KdfDto Kdf, byte[] AuthHash, byte[] AuthHashSalt);
public record VaultRow(long Revision, string BlobJson, DateTime UpdatedUtc);
public record HistoryRow(long Revision, string BlobJson, byte[] Salt, KdfDto Kdf, DateTime CreatedUtc);

public static class Base64
{
    public static bool TryLength(string? value, out int decodedLength)
    {
        decodedLength = 0;
        if (string.IsNullOrEmpty(value)) return false;
        var buffer = new byte[(value.Length * 3 / 4) + 3];
        if (!Convert.TryFromBase64String(value, buffer, out decodedLength)) return false;
        return true;
    }

    public static byte[]? TryDecode(string? value, int expectedLength)
    {
        if (string.IsNullOrEmpty(value)) return null;
        var buffer = new byte[(value.Length * 3 / 4) + 3];
        if (!Convert.TryFromBase64String(value, buffer, out var written) || written != expectedLength) return null;
        return buffer.AsSpan(0, written).ToArray();
    }
}

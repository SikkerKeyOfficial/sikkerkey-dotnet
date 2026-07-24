using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SikkerKey;

/// <summary>
/// On-disk fallback secret cache — the .NET port of the .skc format defined by the
/// SikkerKey CLI. Files are byte-compatible with the CLI and the other SDKs: same key
/// derivation, AES-256-GCM sealing, AAD, envelope, and path, so a cache written by one
/// is readable by all.
/// <para>
/// Strictly opt-in (<see cref="SikkerKeyClient.EnableCache"/>) and inert until then.
/// </para>
/// <code>
///   key   = HKDF-SHA256(ikm = ed25519_seed, salt = vaultId, info = "sikkerkey-cache-v1")  -> 32 bytes
///   entry = AES-256-GCM(key, nonce = random 12B, plaintext = {name,value,fieldNames} JSON,
///                       aad = "sikkerkey-cache-v1\0{vaultId}\0{machineId}\0{secretId}\0{cachedAt}")
/// </code>
/// </summary>
internal sealed class SecretCache
{
    private const int FormatVersion = 1;
    private const string KdfInfo = "sikkerkey-cache-v1";
    private const string FileExt = ".skc";

    // Guards the on-disk filename against traversal; real secret ids are sk_<alnum>.
    private static readonly Regex SafeSecretId = new("^[A-Za-z0-9_-]+$", RegexOptions.Compiled);

    private readonly string _vaultId;
    private readonly string _machineId;
    private readonly byte[] _key;

    internal SecretCache(string vaultId, string machineId, byte[] key)
    {
        _vaultId = vaultId;
        _machineId = machineId;
        _key = key;
    }

    /// <summary>Derive the 32-byte AES-256 cache key from the Ed25519 seed, bound to the vault.</summary>
    public static byte[] DeriveKey(byte[] seed, string vaultId) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, seed, 32,
            salt: Encoding.UTF8.GetBytes(vaultId), info: Encoding.UTF8.GetBytes(KdfInfo));

    // Mirrors SikkerKeyClient.GetBaseDir so the cache lands beside the identity.
    private static string BaseDir() =>
        Environment.GetEnvironmentVariable("SIKKERKEY_HOME")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".sikkerkey");

    internal static string CacheDir(string vaultId) => Path.Combine(BaseDir(), "vaults", vaultId, "cache");

    public void Store(string secretId, string name, string value, string? fieldNames)
    {
        if (!SafeSecretId.IsMatch(secretId))
            throw new ArgumentException($"refusing to cache unsafe secret id '{secretId}'");

        var cachedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, string> { ["value"] = value };
        if (name.Length > 0) payload["name"] = name;
        if (fieldNames != null) payload["fieldNames"] = fieldNames;

        var (nonce, ct) = Seal(_key, JsonSerializer.SerializeToUtf8Bytes(payload), Aad(secretId, cachedAt));
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new Envelope
        {
            V = FormatVersion,
            Nonce = Convert.ToBase64String(nonce),
            Ct = Convert.ToBase64String(ct),
            CachedAt = cachedAt,
        });
        WriteAtomic(FilePath(secretId), envelope);
    }

    /// <summary>Return the cached entry, or null on a miss. A decrypt failure (tampered,
    /// or from a different identity) throws.</summary>
    public CacheResult? Load(string secretId)
    {
        if (!SafeSecretId.IsMatch(secretId)) return null;
        byte[] data;
        try { data = File.ReadAllBytes(FilePath(secretId)); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        return Decode(secretId, data);
    }

    public CacheResult? Decode(string secretId, byte[] data)
    {
        var env = JsonSerializer.Deserialize<Envelope>(data);
        if (env == null || env.V != FormatVersion) return null; // a newer format wrote this; miss

        var nonce = Convert.FromBase64String(env.Nonce);
        var ct = Convert.FromBase64String(env.Ct);
        var pt = Open(_key, nonce, ct, Aad(secretId, env.CachedAt)); // throws on wrong key / tamper
        using var doc = JsonDocument.Parse(pt);
        var root = doc.RootElement;
        return new CacheResult(
            secretId,
            root.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
            root.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "",
            root.TryGetProperty("fieldNames", out var f) && f.ValueKind != JsonValueKind.Null ? f.GetString() : null,
            env.CachedAt);
    }

    private string FilePath(string secretId) => Path.Combine(CacheDir(_vaultId), secretId + FileExt);

    // domain || vault || machine || secret || timestamp, null-separated.
    private byte[] Aad(string secretId, long cachedAt) =>
        Encoding.UTF8.GetBytes($"{KdfInfo}\0{_vaultId}\0{_machineId}\0{secretId}\0{cachedAt}");

    // ── Crypto ──

    private static (byte[] nonce, byte[] ct) Seal(byte[] key, byte[] plaintext, byte[] aad)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        // Match Go's gcm.Seal output: ciphertext || tag(16).
        var ct = new byte[ciphertext.Length + 16];
        Buffer.BlockCopy(ciphertext, 0, ct, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, ct, ciphertext.Length, 16);
        return (nonce, ct);
    }

    private static byte[] Open(byte[] key, byte[] nonce, byte[] ct, byte[] aad)
    {
        if (ct.Length < 16) throw new CryptographicException("ciphertext too short");
        var ciphertext = ct[..^16];
        var tag = ct[^16..];
        var plaintext = new byte[ciphertext.Length];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    // Write via a temp file + rename so a reader never sees a half-written entry.
    private static void WriteAtomic(string path, byte[] data)
    {
        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var tmp = Path.Combine(dir, $".skc-{Environment.ProcessId}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(6))}");
        File.WriteAllBytes(tmp, data);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        try { File.Move(tmp, path, overwrite: true); }
        catch { try { File.Delete(tmp); } catch { /* ignore */ } throw; }
    }

    private sealed class Envelope
    {
        [JsonPropertyName("v")] public int V { get; set; }
        [JsonPropertyName("nonce")] public string Nonce { get; set; } = "";
        [JsonPropertyName("ct")] public string Ct { get; set; } = "";
        [JsonPropertyName("cachedAt")] public long CachedAt { get; set; }
    }
}

internal sealed record CacheResult(string SecretId, string Name, string Value, string? FieldNames, long CachedAt);

/// <summary>Options for <see cref="SikkerKeyClient.EnableCache"/>.</summary>
public sealed class CacheOptions
{
    /// <summary>Oldest a cached value may be to still be served during an outage. Null = no expiry.</summary>
    public TimeSpan? MaxAge { get; init; }

    /// <summary>Called when a value is served from the cache — for your own logging or
    /// metrics. Receives the secret id and the cached-at epoch seconds. The SDK itself
    /// emits nothing; a fallback is otherwise transparent.</summary>
    public Action<string, long>? OnFallback { get; init; }
}

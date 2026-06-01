using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SikkerKey;

/// <summary>Secret metadata returned by list operations.</summary>
public record SecretListItem(string Id, string Name, string? FieldNames, string? ProjectId);

/// <summary>Status of a watched secret change.</summary>
public enum WatchStatus { Changed, Deleted, AccessDenied, Error }

/// <summary>Event delivered to a watch callback when a secret changes.</summary>
public record WatchEvent(
    string SecretId,
    WatchStatus Status,
    string? Value = null,
    Dictionary<string, string>? Fields = null,
    string? Error = null
);

/// <summary>
/// SikkerKey SDK client — manage secrets from a SikkerKey vault.
/// <para>
/// Quick start:
/// <code>
/// var sk = SikkerKeyClient.Create("vault_abc123");
/// var secret = await sk.GetSecretAsync("sk_a1b2c3d4e5");
/// </code>
/// </para>
/// </summary>
public sealed class SikkerKeyClient : IDisposable
{
    private readonly Identity _identity;
    private readonly Ed25519PrivateKey _privateKey;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };

    private static readonly HashSet<int> RetryableCodes = [429, 503];
    private const int MaxRetries = 3;
    private static readonly int[] BackoffMs = [1000, 2000, 4000];
    private const string DefaultApiUrl = "https://api.sikkerkey.com";

    private readonly ConcurrentDictionary<string, Action<WatchEvent>> _watchers = new();
    private CancellationTokenSource? _pollCts;
    private Task? _pollTask;
    private int _pollIntervalMs = 15_000;
    private readonly object _pollLock = new();
    private bool _disposed;

    private SikkerKeyClient(Identity identity, Ed25519PrivateKey privateKey)
    {
        _identity = identity;
        _privateKey = privateKey;
    }

    /// <summary>Create a client. Pass a vault ID, path to identity.json, or null to auto-detect.</summary>
    public static SikkerKeyClient Create(string? vaultOrPath = null)
    {
        var identityFile = ResolveIdentity(vaultOrPath);
        var (identity, privateKey) = LoadIdentity(identityFile);
        return new SikkerKeyClient(identity, privateKey);
    }

    /// <summary>
    /// Bootstrap a memory-only ephemeral identity for serverless / read-only
    /// filesystem environments that have no identity on disk.
    /// <para>
    /// Generates an Ed25519 keypair in memory, registers an ephemeral machine
    /// with the enrollment token, and returns a client whose identity lives only
    /// in process memory; nothing is written to disk. Enrollment happens once,
    /// here; the returned client then behaves exactly like one from
    /// <see cref="Create"/>. The ephemeral machine lives for the lifetime set on
    /// the token; reading after it expires throws <see cref="AuthenticationException"/>,
    /// so size the token's machine lifetime to the workload. The common path is
    /// to read secrets at startup and hold the values.
    /// </para>
    /// </summary>
    /// <param name="vaultId">The vault ID (<c>vault_...</c>).</param>
    /// <param name="token">The plaintext of an enrollment token.</param>
    /// <param name="hostname">Hostname recorded on the machine. Defaults to <c>$HOSTNAME</c>, then <c>serverless</c>. Must match the token's hostname pattern if one is set.</param>
    /// <param name="name">Optional machine name. Overridden when the token defines a name pattern.</param>
    public static async Task<SikkerKeyClient> BootstrapInMemoryAsync(
        string vaultId,
        string token,
        string? hostname = null,
        string? name = null)
    {
        if (string.IsNullOrEmpty(vaultId))
            throw new ConfigurationException("BootstrapInMemoryAsync requires a vault ID");
        if (string.IsNullOrEmpty(token))
            throw new ConfigurationException("BootstrapInMemoryAsync requires an enrollment token");

        // SikkerKey is a managed service; the API URL is fixed. The env override is for local dev only.
        var rawUrl = Environment.GetEnvironmentVariable("SIKKERKEY_API_URL") ?? DefaultApiUrl;
        if (!rawUrl.StartsWith("https://") && !rawUrl.StartsWith("http://localhost"))
            throw new ConfigurationException($"API URL must use HTTPS: {rawUrl}. Use http://localhost only for local development.");
        var apiUrl = rawUrl.TrimEnd('/');

        // Generate the keypair in memory. The private key never leaves this process.
        var (privateKey, publicKeyB64) = Ed25519PrivateKey.Generate();

        var host = hostname ?? Environment.GetEnvironmentVariable("HOSTNAME") ?? "serverless";
        var bodyDict = new Dictionary<string, string>
        {
            ["token"] = token,
            ["publicKey"] = publicKeyB64,
            ["hostname"] = host,
        };
        if (name != null) bodyDict["name"] = name;
        var body = JsonSerializer.Serialize(bodyDict);

        var identity = await EnrollRegisterAsync(apiUrl, vaultId, body);
        return new SikkerKeyClient(identity, privateKey);
    }

    public string MachineId => _identity.MachineId;
    public string MachineName => _identity.MachineName;
    public string VaultId => _identity.VaultId;
    public string ApiUrl => _identity.ApiUrl;

    // ── Read ──

    /// <summary>Fetch a secret value by ID.</summary>
    public async Task<string> GetSecretAsync(string secretId)
    {
        var body = await RequestAsync("GET", $"/v1/secret/{secretId}");
        return JsonDocument.Parse(body).RootElement.GetProperty("value").GetString()!;
    }

    /// <summary>Fetch a structured secret as a dictionary.</summary>
    public async Task<Dictionary<string, string>> GetFieldsAsync(string secretId)
    {
        var raw = await GetSecretAsync(secretId);
        try
        {
            var obj = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(raw)
                ?? throw new Exception();
            return obj.ToDictionary(kv => kv.Key, kv => kv.Value.ToString());
        }
        catch
        {
            throw new SecretStructureException($"Secret {secretId} is not a structured secret");
        }
    }

    /// <summary>Fetch a single field from a structured secret.</summary>
    public async Task<string> GetFieldAsync(string secretId, string field)
    {
        var fields = await GetFieldsAsync(secretId);
        if (!fields.TryGetValue(field, out var value))
            throw new FieldNotFoundException(
                $"Field '{field}' not found in secret {secretId}. Available: {string.Join(", ", fields.Keys)}");
        return value;
    }

    // ── List ──

    /// <summary>List all secrets this machine can access.</summary>
    public async Task<List<SecretListItem>> ListSecretsAsync()
    {
        var body = await RequestAsync("GET", "/v1/secrets");
        return ParseSecretList(body);
    }

    /// <summary>List secrets in a specific project.</summary>
    public async Task<List<SecretListItem>> ListSecretsByProjectAsync(string projectId)
    {
        var body = await RequestAsync("POST", "/v1/secrets/list", JsonObj(("projectId", projectId)));
        return ParseSecretList(body);
    }

    // ── Export ──

    /// <summary>Export all accessible secrets as a flat key-value map (single round trip).</summary>
    public async Task<Dictionary<string, string>> ExportAsync(string? projectId = null)
    {
        var payload = projectId != null ? JsonObj(("projectId", projectId)) : null;
        var body = await RequestAsync("POST", "/v1/secrets/export", payload);
        var doc = JsonDocument.Parse(body).RootElement;
        var result = new Dictionary<string, string>();
        foreach (var entry in doc.GetProperty("secrets").EnumerateArray())
        {
            var envName = ToEnvName(entry.GetProperty("name").GetString()!);
            var val = entry.GetProperty("value").GetString()!;
            var hasFields = entry.TryGetProperty("fieldNames", out var fn) && fn.ValueKind != JsonValueKind.Null;
            if (hasFields)
            {
                try
                {
                    var fields = JsonSerializer.Deserialize<Dictionary<string, string>>(val);
                    if (fields != null && fields.Count > 0)
                    {
                        foreach (var (k, v) in fields) result[$"{envName}_{ToEnvName(k)}"] = v;
                        continue;
                    }
                }
                catch { /* not structured */ }
            }
            result[envName] = val;
        }
        return result;
    }

    // ── Watch ──

    /// <summary>
    /// Register a callback for changes to a secret. Starts background polling if not already running.
    /// The callback is invoked on the polling thread when the secret changes, is deleted, or access is denied.
    /// </summary>
    public void Watch(string secretId, Action<WatchEvent> callback)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretId);
        ArgumentNullException.ThrowIfNull(callback);

        _watchers[secretId] = callback;
        EnsurePolling();
    }

    /// <summary>
    /// Remove the watch callback for a secret. Stops background polling if no watches remain.
    /// </summary>
    public void Unwatch(string secretId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _watchers.TryRemove(secretId, out _);

        if (_watchers.IsEmpty)
            StopPolling();
    }

    /// <summary>
    /// Set the polling interval in seconds. Minimum 10 seconds. Default is 15.
    /// Takes effect on the next poll cycle.
    /// </summary>
    public void SetPollInterval(int seconds)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _pollIntervalMs = Math.Max(10, seconds) * 1000;
    }

    /// <summary>
    /// Cancel all watches and stop background polling.
    /// </summary>
    public void Close()
    {
        StopPolling();
        _watchers.Clear();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Close();
        _http.Dispose();
    }

    private void EnsurePolling()
    {
        lock (_pollLock)
        {
            if (_pollTask is { IsCompleted: false }) return;

            _pollCts = new CancellationTokenSource();
            var token = _pollCts.Token;
            _pollTask = Task.Run(async () => await PollLoopAsync(token), token);
        }
    }

    private void StopPolling()
    {
        lock (_pollLock)
        {
            if (_pollCts == null) return;
            _pollCts.Cancel();
            _pollCts.Dispose();
            _pollCts = null;
            _pollTask = null;
        }
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_pollIntervalMs, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            var ids = _watchers.Keys.ToList();
            if (ids.Count == 0) return;

            Dictionary<string, JsonElement>? changes;
            try
            {
                var payload = JsonSerializer.Serialize(new { watch = ids });
                var body = await RequestAsync("POST", "/v1/secrets/poll", payload);
                var doc = JsonDocument.Parse(body).RootElement;
                changes = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                    doc.GetProperty("changes").GetRawText());
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                // Poll request failed - skip this cycle, retry next interval
                continue;
            }

            if (changes == null) continue;

            foreach (var (secretId, statusElement) in changes)
            {
                if (!_watchers.TryGetValue(secretId, out var callback)) continue;

                var status = statusElement.GetProperty("status").GetString();

                switch (status)
                {
                    case "changed":
                        try
                        {
                            var value = await GetSecretAsync(secretId);
                            Dictionary<string, string>? fields = null;
                            try
                            {
                                fields = JsonSerializer.Deserialize<Dictionary<string, string>>(value);
                            }
                            catch
                            {
                                // Not a structured secret - that's fine
                            }
                            callback(new WatchEvent(secretId, WatchStatus.Changed, value, fields));
                        }
                        catch (Exception ex)
                        {
                            callback(new WatchEvent(secretId, WatchStatus.Error, Error: ex.Message));
                        }
                        break;

                    case "deleted":
                        callback(new WatchEvent(secretId, WatchStatus.Deleted));
                        _watchers.TryRemove(secretId, out _);
                        break;

                    case "access_denied":
                        callback(new WatchEvent(secretId, WatchStatus.AccessDenied));
                        _watchers.TryRemove(secretId, out _);
                        break;

                    default:
                        callback(new WatchEvent(secretId, WatchStatus.Error,
                            Error: $"Unknown poll status: {status}"));
                        break;
                }
            }

            if (_watchers.IsEmpty)
                return;
        }
    }

    // ── List Vaults ──

    /// <summary>List all vault IDs registered on this machine.</summary>
    public static List<string> ListVaults()
    {
        var vaultsDir = GetVaultsDir();
        if (!Directory.Exists(vaultsDir)) return [];
        return Directory.GetDirectories(vaultsDir)
            .Where(d => File.Exists(Path.Combine(d, "identity.json")))
            .Select(Path.GetFileName)
            .Where(n => n != null)
            .Select(n => n!)
            .Order()
            .ToList();
    }

    // ── Internal HTTP ──

    private async Task<string> RequestAsync(string method, string path, string? body = null, int expectStatus = 200)
    {
        SikkerKeyException? lastError = null;

        for (var attempt = 0; attempt <= MaxRetries; attempt++)
        {
            if (attempt > 0)
                await Task.Delay(BackoffMs[Math.Min(attempt - 1, BackoffMs.Length - 1)]);

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var nonceBytes = RandomNumberGenerator.GetBytes(16);
            var nonce = Convert.ToBase64String(nonceBytes);
            var bodyHash = Sha256Hex(body ?? "");
            var signPayload = $"{method}:{path}:{timestamp}:{nonce}:{bodyHash}";
            var signature = Convert.ToBase64String(_privateKey.Sign(Encoding.UTF8.GetBytes(signPayload)));

            var url = _identity.ApiUrl + path;
            var request = new HttpRequestMessage(new HttpMethod(method), url);
            request.Headers.Add("X-Machine-Id", _identity.MachineId);
            request.Headers.Add("X-Timestamp", timestamp);
            request.Headers.Add("X-Nonce", nonce);
            request.Headers.Add("X-Signature", signature);

            if (body != null)
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");

            int code;
            string responseBody;
            try
            {
                var response = await _http.SendAsync(request);
                code = (int)response.StatusCode;
                responseBody = await response.Content.ReadAsStringAsync();
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
            {
                lastError = new ApiException($"Network error: {e.Message}", 0);
                continue;
            }

            if (code == expectStatus) return responseBody;

            string errorMsg;
            try { errorMsg = JsonDocument.Parse(responseBody).RootElement.GetProperty("error").GetString() ?? responseBody; }
            catch { errorMsg = string.IsNullOrEmpty(responseBody) ? $"HTTP {code}" : responseBody; }

            var exception = MakeException(code, errorMsg);

            if (RetryableCodes.Contains(code) && attempt < MaxRetries)
            {
                lastError = exception;
                continue;
            }

            throw exception;
        }

        throw lastError ?? new ApiException($"Request failed after {MaxRetries} retries", 0);
    }

    private static async Task<Identity> EnrollRegisterAsync(string apiUrl, string vaultId, string body)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var url = $"{apiUrl}/v1/{vaultId}/enroll/register";
        var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

        int code;
        string responseBody;
        try
        {
            var response = await http.SendAsync(request);
            code = (int)response.StatusCode;
            responseBody = await response.Content.ReadAsStringAsync();
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            throw new ApiException($"Enrollment network error: {e.Message}", 0);
        }

        if (code is >= 200 and < 300)
        {
            var doc = JsonDocument.Parse(responseBody).RootElement;
            var machineId = doc.TryGetProperty("machineId", out var mid) ? mid.GetString() : null;
            var vId = doc.TryGetProperty("vaultId", out var vd) ? vd.GetString() : null;
            if (string.IsNullOrEmpty(machineId) || string.IsNullOrEmpty(vId))
                throw new ApiException("Malformed enrollment response", code);
            var machineName = doc.TryGetProperty("machineName", out var mn) ? mn.GetString() ?? "" : "";
            return new Identity(machineId!, machineName, vId!, apiUrl, "");
        }

        string errorMsg;
        try { errorMsg = JsonDocument.Parse(responseBody).RootElement.GetProperty("error").GetString() ?? responseBody; }
        catch { errorMsg = string.IsNullOrEmpty(responseBody) ? $"HTTP {code}" : responseBody; }
        throw MakeException(code, errorMsg);
    }

    // ── Identity resolution ──

    private static string GetBaseDir() =>
        Environment.GetEnvironmentVariable("SIKKERKEY_HOME")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".sikkerkey");

    private static string GetVaultsDir() => Path.Combine(GetBaseDir(), "vaults");

    private static string ResolveIdentity(string? vaultOrPath)
    {
        if (vaultOrPath != null && (vaultOrPath.StartsWith('/') || vaultOrPath.Contains("identity.json")))
            return vaultOrPath;

        if (vaultOrPath != null)
        {
            var vaultId = vaultOrPath.StartsWith("vault_") ? vaultOrPath : $"vault_{vaultOrPath}";
            var filePath = Path.Combine(GetVaultsDir(), vaultId, "identity.json");
            if (File.Exists(filePath)) return filePath;
            throw new ConfigurationException($"No identity found for vault '{vaultId}'. Expected: {filePath}. Run the bootstrap command first.");
        }

        var envPath = Environment.GetEnvironmentVariable("SIKKERKEY_IDENTITY");
        if (!string.IsNullOrEmpty(envPath)) return envPath;

        var vaultsDir = GetVaultsDir();
        if (Directory.Exists(vaultsDir))
        {
            var found = Directory.GetDirectories(vaultsDir)
                .Where(d => File.Exists(Path.Combine(d, "identity.json")))
                .Select(d => Path.Combine(d, "identity.json"))
                .ToList();

            if (found.Count == 1) return found[0];
            if (found.Count > 1)
            {
                var names = string.Join(", ", found.Select(f => Path.GetFileName(Path.GetDirectoryName(f))));
                throw new ConfigurationException($"Multiple vaults registered: {names}. Specify which vault to use: SikkerKeyClient.Create(\"vault_id\")");
            }
        }

        throw new ConfigurationException($"No SikkerKey identity found. Run the bootstrap command first.\n  Checked: {vaultsDir}/*/identity.json");
    }

    private static (Identity, Ed25519PrivateKey) LoadIdentity(string filePath)
    {
        if (!File.Exists(filePath))
            throw new ConfigurationException($"Identity file not found: {filePath}. Run the bootstrap command first.");

        Identity identity;
        try { identity = JsonSerializer.Deserialize<Identity>(File.ReadAllText(filePath))!; }
        catch (Exception e) { throw new ConfigurationException($"Failed to parse identity file: {e.Message}", e); }

        if (!identity.ApiUrl.StartsWith("https://") && !identity.ApiUrl.StartsWith("http://localhost"))
            throw new ConfigurationException($"API URL must use HTTPS: {identity.ApiUrl}. Use http://localhost only for local development.");

        if (!File.Exists(identity.PrivateKeyPath))
            throw new ConfigurationException($"Private key not found: {identity.PrivateKeyPath}");

        Ed25519PrivateKey privateKey;
        try { privateKey = Ed25519PrivateKey.Load(identity.PrivateKeyPath); }
        catch (Exception e) { throw new ConfigurationException($"Failed to load private key: {e.Message}", e); }

        return (identity, privateKey);
    }

    // ── Helpers ──

    private static ApiException MakeException(int code, string message) => code switch
    {
        401 => new AuthenticationException(message),
        403 => new AccessDeniedException(message),
        404 => new NotFoundException(message),
        409 => new ConflictException(message),
        429 => new RateLimitedException(message),
        503 => new ServerSealedException(message),
        _ => new ApiException(message, code),
    };

    private static string JsonObj(params (string key, object value)[] pairs)
    {
        var dict = pairs.ToDictionary(p => p.key, p => p.value);
        return JsonSerializer.Serialize(dict);
    }

    private static List<SecretListItem> ParseSecretList(string body)
    {
        var doc = JsonDocument.Parse(body).RootElement;
        return doc.GetProperty("secrets").EnumerateArray().Select(s =>
            new SecretListItem(
                s.GetProperty("id").GetString()!,
                s.GetProperty("name").GetString()!,
                s.TryGetProperty("fieldNames", out var fn) && fn.ValueKind != JsonValueKind.Null ? fn.GetString() : null,
                s.TryGetProperty("projectId", out var pi) && pi.ValueKind != JsonValueKind.Null ? pi.GetString() : null
            )).ToList();
    }

    private static string Sha256Hex(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ToEnvName(string name)
    {
        var sb = new StringBuilder();
        var prevUnderscore = false;
        foreach (var c in name.ToUpperInvariant())
        {
            if (c is >= 'A' and <= 'Z' or >= '0' and <= '9') { sb.Append(c); prevUnderscore = false; }
            else if (!prevUnderscore) { sb.Append('_'); prevUnderscore = true; }
        }
        return sb.ToString().Trim('_');
    }
}

// ── Internal types ──

internal record Identity(
    [property: JsonPropertyName("machineId")] string MachineId,
    [property: JsonPropertyName("machineName")] string MachineName,
    [property: JsonPropertyName("vaultId")] string VaultId,
    [property: JsonPropertyName("apiUrl")] string ApiUrl,
    [property: JsonPropertyName("privateKeyPath")] string PrivateKeyPath
);

/// <summary>Wrapper around Ed25519 key loaded from PEM via NSec.</summary>
internal sealed class Ed25519PrivateKey
{
    private readonly NSec.Cryptography.Key _key;

    private Ed25519PrivateKey(NSec.Cryptography.Key key) => _key = key;

    /// <summary>
    /// Generate a new in-memory Ed25519 key. Returns the wrapper and the raw
    /// 32-byte public key as standard base64 (for enrollment).
    /// </summary>
    public static (Ed25519PrivateKey, string) Generate()
    {
        var algorithm = NSec.Cryptography.SignatureAlgorithm.Ed25519;
        var key = NSec.Cryptography.Key.Create(algorithm);
        var rawPub = key.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey);
        return (new Ed25519PrivateKey(key), Convert.ToBase64String(rawPub));
    }

    public static Ed25519PrivateKey Load(string pemPath)
    {
        var pem = File.ReadAllText(pemPath);
        var base64 = pem
            .Replace("-----BEGIN PRIVATE KEY-----", "")
            .Replace("-----END PRIVATE KEY-----", "")
            .Replace("\n", "").Replace("\r", "").Trim();
        var pkcs8 = Convert.FromBase64String(base64);

        // PKCS#8 Ed25519: last 32 bytes are the private key seed
        if (pkcs8.Length < 48)
            throw new InvalidOperationException("Invalid Ed25519 PKCS#8 key length");

        var seed = pkcs8[^32..];
        var algorithm = NSec.Cryptography.SignatureAlgorithm.Ed25519;
        var key = NSec.Cryptography.Key.Import(algorithm, seed, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
        return new Ed25519PrivateKey(key);
    }

    public byte[] Sign(byte[] message)
    {
        var algorithm = NSec.Cryptography.SignatureAlgorithm.Ed25519;
        return algorithm.Sign(_key, message);
    }
}

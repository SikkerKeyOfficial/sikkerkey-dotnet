# SikkerKey .NET SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0+-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com)
[![C#](https://img.shields.io/badge/C%23-12-239120?logo=csharp&logoColor=white)](https://learn.microsoft.com/en-us/dotnet/csharp/)

Use the official SikkerKey .NET SDK to give a C# application read access to the secrets its machine is authorized to use.

The SDK can:

- Read standard and structured secrets asynchronously.
- List the secrets available to a machine.
- Export accessible secrets as application-friendly key/value pairs.
- Monitor selected secrets for changes.
- Use persistent machine identities or memory-only ephemeral identities.
- Keep an optional encrypted fallback cache for temporary service or network outages.

After the client is initialized, every secret request is authenticated with the machine's Ed25519 identity. The SDK targets .NET 8 and uses `NSec.Cryptography` for Ed25519 key handling and request signing.

## Requirements

- .NET 8 or newer.
- A SikkerKey vault.
- A machine identity with access to the secrets your application needs.

Persistent applications use an identity provisioned on the host. Serverless jobs and other short-lived workloads can enroll an ephemeral machine in memory with an enrollment token.

## Install the SDK

```bash
dotnet add package SikkerKey
```

To install the version represented by this source:

```bash
dotnet add package SikkerKey --version 1.3.0
```

## Read your first secret

Create a client for your vault and pass a secret ID to `GetSecretAsync`:

```csharp
using SikkerKey;

using var sikkerKey = SikkerKeyClient.Create("vault_abc123");
var apiKey = await sikkerKey.GetSecretAsync("sk_stripe_key");
```

The SDK loads the machine identity from:

```text
~/.sikkerkey/vaults/vault_abc123/identity.json
```

It signs the request with the machine's Ed25519 private key and returns the secret value as a `string`. Your application's access remains limited by the machine's configured access.

Secret reads and other network operations return `Task` values and should be awaited.

## Create a client

Choose the form that fits how identities are installed in your environment:

```csharp
// Select a registered vault.
using var byVault = SikkerKeyClient.Create("vault_abc123");

// Load a specific identity file.
using var byPath =
    SikkerKeyClient.Create("/etc/sikkerkey/vaults/vault_abc123/identity.json");

// Use SIKKERKEY_IDENTITY or auto-select the only registered vault.
using var automatically = SikkerKeyClient.Create();
```

When no argument is supplied, the SDK checks `SIKKERKEY_IDENTITY` first. If that variable is not set, it uses the only registered vault under `~/.sikkerkey/vaults/`.

If more than one vault is registered, select a vault explicitly. Missing identities, unreadable keys, invalid identity files, and ambiguous vault selection produce a `ConfigurationException`.

The `vault_` prefix is added when a vault ID is supplied without it.

### Use a different identity directory

Set `SIKKERKEY_HOME` to move the SDK's base directory:

```bash
export SIKKERKEY_HOME=/var/lib/sikkerkey
```

The SDK will look for identities under:

```text
/var/lib/sikkerkey/vaults/<vault-id>/identity.json
```

## Use an ephemeral identity

`BootstrapInMemoryAsync` is designed for short-lived or read-only environments where an identity should not be stored on disk.

```csharp
using var sikkerKey = await SikkerKeyClient.BootstrapInMemoryAsync(
    Environment.GetEnvironmentVariable("SIKKERKEY_VAULT_ID")!,
    Environment.GetEnvironmentVariable("SIKKERKEY_ENROLLMENT_TOKEN")!
);

var databaseUrl = await sikkerKey.GetSecretAsync("sk_db_prod");
```

During bootstrap, the SDK:

1. Generates an Ed25519 key pair in memory.
2. Uses the enrollment token to register an ephemeral machine.
3. Keeps the private key inside the running process.
4. Returns a client ready to read the secrets allowed by the token's access policy.

Nothing is written to disk by `BootstrapInMemoryAsync`. The private key disappears when the process exits.

The enrollment token registers the machine; it does not read secrets itself. The resulting machine remains subject to the token's permitted scope, use limit, hostname rules, and machine lifetime. Once the machine expires, subsequent reads produce an `AuthenticationException`.

### Set the machine hostname and name

```csharp
using var sikkerKey = await SikkerKeyClient.BootstrapInMemoryAsync(
    vaultId,
    enrollmentToken,
    hostname: "worker-1",
    name: "invoice-runner"
);
```

`hostname` defaults to the `HOSTNAME` environment variable and then to `serverless`. A name pattern configured on the enrollment token takes precedence over the `name` argument.

For reliable ephemeral deployments:

- Set a machine lifetime long enough for the workload to finish.
- Allow enough token uses for expected cold starts and concurrency.
- Use a unique name pattern such as `worker-{uuid8}`.
- Ensure the vault's IP allowlist permits the workload's outbound address when an allowlist is enabled.

Each active ephemeral machine uses a machine slot until it expires.

## Read secrets

### Standard secrets

Use `GetSecretAsync` when you need the complete value:

```csharp
var apiKey = await sikkerKey.GetSecretAsync("sk_stripe_prod");
```

### Structured secrets

Use `GetFieldsAsync` to read a structured secret as field names and values:

```csharp
var database = await sikkerKey.GetFieldsAsync("sk_db_prod");

var host = database["host"];
var username = database["username"];
var password = database["password"];
```

`GetFieldsAsync` expects the stored value to be a JSON object. Each property is represented as a string in the returned `Dictionary<string, string>`. It throws `SecretStructureException` when the value cannot be read as an object.

Use `GetFieldAsync` when your application needs one field:

```csharp
var password =
    await sikkerKey.GetFieldAsync("sk_db_prod", "password");
```

If the field is missing, `FieldNotFoundException` includes the available field names.

## Discover accessible secrets

`ListSecretsAsync` returns metadata for every secret the machine can access:

```csharp
var secrets = await sikkerKey.ListSecretsAsync();

foreach (var secret in secrets)
{
    Console.WriteLine($"{secret.Id}: {secret.Name}");
}
```

Use `ListSecretsByProjectAsync` to limit the result to one project:

```csharp
var productionSecrets =
    await sikkerKey.ListSecretsByProjectAsync("proj_production");
```

Each `SecretListItem` contains:

| Property | Type | Meaning |
|---|---|---|
| `Id` | `string` | Secret ID used by read methods |
| `Name` | `string` | Display name |
| `FieldNames` | `string?` | Optional structured-field metadata |
| `ProjectId` | `string?` | Owning project, when present |

Listing returns metadata, not secret values.

## Export secrets for application configuration

`ExportAsync` retrieves accessible values in one request and returns a flat `Dictionary<string, string>`:

```csharp
var configuration = await sikkerKey.ExportAsync();

foreach (var (name, value) in configuration)
{
    Environment.SetEnvironmentVariable(name, value);
}
```

Limit the export to a project when the application only needs that scope:

```csharp
var productionConfiguration =
    await sikkerKey.ExportAsync("proj_production");
```

Names are converted to uppercase environment-style keys. Unsupported characters become underscores. Structured secrets are expanded into one entry per field:

```text
API_KEY
DB_CREDENTIALS_HOST
DB_CREDENTIALS_USERNAME
DB_CREDENTIALS_PASSWORD
```

## Continue reads during temporary outages

The fallback cache is disabled by default. Enable it for persistent hosts that should continue using a recently retrieved value when SikkerKey or the network is temporarily unreachable:

```csharp
using var sikkerKey = SikkerKeyClient
    .Create("vault_abc123")
    .EnableCache();
```

After the cache is enabled, each successful `GetSecretAsync` read stores an encrypted entry under:

```text
~/.sikkerkey/vaults/<vault-id>/cache/
```

`GetFieldsAsync` and `GetFieldAsync` use `GetSecretAsync`, so their successful reads are cached as well. Cache writes are best-effort: a cache storage problem does not turn a successful live read into an application failure.

The SDK can return a cached value after:

- A network connection failure or request timeout.
- HTTP `502`, `503`, or `504`.
- Edge or origin-connectivity responses `520` through `527`, or `530`.

An authoritative response is never replaced by a cached value. Authentication failures, revoked access, missing secrets, rate limits, and other application responses continue to reach your code normally.

Cache files use AES-256-GCM with a key derived from the machine's Ed25519 identity and vault ID. A file cannot be decrypted without the matching machine identity, and tampered entries are rejected.

The cache format is compatible with the SikkerKey CLI and other SikkerKey SDKs that support the same `.skc` format.

### Limit cache age

Set `MaxAge` to the maximum age your application accepts during an outage:

```csharp
using var sikkerKey = SikkerKeyClient
    .Create("vault_abc123")
    .EnableCache(new CacheOptions
    {
        MaxAge = TimeSpan.FromHours(1)
    });
```

Without `MaxAge`, cached values do not expire automatically. They are still only read when the live service cannot be reached.

### Observe fallback use

Use `OnFallback` to record when the SDK serves a cached value:

```csharp
using var sikkerKey = SikkerKeyClient
    .Create("vault_abc123")
    .EnableCache(new CacheOptions
    {
        MaxAge = TimeSpan.FromHours(1),
        OnFallback = (secretId, cachedAt) =>
        {
            Console.WriteLine(
                $"Used cached value for {secretId} from epoch {cachedAt}");
        }
    });
```

The SDK does not emit a cache-fallback message unless you supply this callback.

The fallback cache is intended for a host with a persistent, protected identity directory. It is not useful for a memory-only identity that disappears when the process exits.

## Monitor secrets for changes

Use `Watch` when your application should react after a secret changes, is deleted, or becomes inaccessible:

```csharp
sikkerKey.Watch("sk_db_credentials", change =>
{
    switch (change.Status)
    {
        case WatchStatus.Changed:
            var username = change.Fields?["username"];
            var password = change.Fields?["password"];
            Console.WriteLine(
                $"Database credentials changed for {change.SecretId}");
            break;

        case WatchStatus.Deleted:
            Console.WriteLine($"{change.SecretId} was deleted");
            break;

        case WatchStatus.AccessDenied:
            Console.WriteLine($"Access to {change.SecretId} was removed");
            break;

        case WatchStatus.Error:
            Console.WriteLine(
                $"Could not retrieve the update: {change.Error}");
            break;
    }
});
```

The SDK polls on a background task every 15 seconds by default. Your callback executes as part of that polling task, so hand off slow or blocking work to your application's own queue or background service.

For `Changed` events:

- `change.Value` contains the new complete value.
- `change.Fields` contains parsed fields when the value is a structured JSON object whose values can be read as strings.

Deleted and inaccessible secrets are automatically removed from the watch list. A failed polling request is retried during the next polling interval.

### Change the polling interval

```csharp
sikkerKey.SetPollInterval(30);
```

The value is in seconds. Values below 10 are raised to 10 seconds and the new interval takes effect on the next cycle.

### Stop monitoring

```csharp
// Stop one watch.
sikkerKey.Unwatch("sk_db_credentials");

// Stop all watches and shut down the polling task.
sikkerKey.Close();
```

`SikkerKeyClient` implements `IDisposable`. Prefer `using` so the HTTP client and polling resources are released with the application scope:

```csharp
using var sikkerKey = SikkerKeyClient.Create("vault_abc123");
var password =
    await sikkerKey.GetFieldAsync("sk_db_credentials", "password");
```

Calling `Close` stops monitoring but leaves the client available for subsequent reads. Calling `Dispose` releases the client completely.

## Work with more than one vault

Create one client per vault:

```csharp
using var production = SikkerKeyClient.Create("vault_production");
using var staging = SikkerKeyClient.Create("vault_staging");

var productionKey =
    await production.GetSecretAsync("sk_api_key");
var stagingKey =
    await staging.GetSecretAsync("sk_api_key");
```

List the vault identities registered under `SIKKERKEY_HOME`:

```csharp
var vaultIds = SikkerKeyClient.ListVaults();
```

`ListVaults` is synchronous and returns vault IDs in alphabetical order.

## Inspect the active machine

The client exposes the identity it is using:

```csharp
Console.WriteLine(sikkerKey.MachineId);
Console.WriteLine(sikkerKey.MachineName);
Console.WriteLine(sikkerKey.VaultId);
Console.WriteLine(sikkerKey.ApiUrl);
```

| Property | Meaning |
|---|---|
| `MachineId` | Machine UUID assigned by SikkerKey |
| `MachineName` | Machine name assigned during provisioning or enrollment |
| `VaultId` | Vault associated with the machine identity |
| `ApiUrl` | Service endpoint stored in the identity |

## Handle errors

The SDK's exception hierarchy starts with `SikkerKeyException`:

```csharp
using SikkerKey;

try
{
    var value = await sikkerKey.GetSecretAsync("sk_example");
}
catch (NotFoundException error)
{
    Console.WriteLine($"Secret not found: {error.Message}");
}
catch (AccessDeniedException error)
{
    Console.WriteLine($"Access denied: {error.Message}");
}
catch (AuthenticationException error)
{
    Console.WriteLine($"Authentication failed: {error.Message}");
}
catch (RateLimitedException error)
{
    Console.WriteLine($"Request remained rate-limited: {error.Message}");
}
catch (ApiException error)
{
    Console.WriteLine(
        $"SikkerKey returned HTTP {error.HttpStatus}: {error.Message}");
}
catch (ConfigurationException error)
{
    Console.WriteLine(
        $"The machine identity could not be loaded: {error.Message}");
}
```

### Exception reference

| Exception | When it is used |
|---|---|
| `ConfigurationException` | Identity, key, vault-selection, or bootstrap configuration is invalid |
| `AuthenticationException` | HTTP `401` |
| `AccessDeniedException` | HTTP `403` |
| `NotFoundException` | HTTP `404` |
| `ConflictException` | HTTP `409` |
| `RateLimitedException` | HTTP `429` |
| `ServerSealedException` | HTTP `503` |
| `ApiException` | Another HTTP or network error; inspect `HttpStatus` |
| `SecretStructureException` | `GetFieldsAsync` or `GetFieldAsync` received a non-structured value |
| `FieldNotFoundException` | The requested structured field does not exist |

Network failures and request timeouts use an `ApiException` with `HttpStatus == 0`.

### Retries and timeout

Authenticated secret requests automatically retry network failures, request timeouts, and HTTP `429` or `503` responses up to three times. Retries wait 1, 2, and 4 seconds, and every attempt receives a fresh timestamp and nonce.

The shared HTTP client uses a 15-second request timeout. Other HTTP responses are returned immediately as their matching exception.

## Feature-to-API reference

| What you want to do | SDK API | Result |
|---|---|---|
| Create a client from disk | `SikkerKeyClient.Create(vaultOrPath?)` | `SikkerKeyClient` |
| Create a memory-only ephemeral client | `SikkerKeyClient.BootstrapInMemoryAsync(vaultId, token, hostname?, name?)` | `Task<SikkerKeyClient>` |
| List locally registered vaults | `SikkerKeyClient.ListVaults()` | `List<string>` |
| Enable outage fallback | `EnableCache(options?)` | The same `SikkerKeyClient` |
| Read a standard secret | `GetSecretAsync(secretId)` | `Task<string>` |
| Read every structured field | `GetFieldsAsync(secretId)` | `Task<Dictionary<string, string>>` |
| Read one structured field | `GetFieldAsync(secretId, field)` | `Task<string>` |
| List accessible secrets | `ListSecretsAsync()` | `Task<List<SecretListItem>>` |
| List accessible secrets in a project | `ListSecretsByProjectAsync(projectId)` | `Task<List<SecretListItem>>` |
| Export accessible values | `ExportAsync(projectId?)` | `Task<Dictionary<string, string>>` |
| Monitor a secret | `Watch(secretId, callback)` | `void` |
| Stop monitoring one secret | `Unwatch(secretId)` | `void` |
| Set the polling interval | `SetPollInterval(seconds)` | `void` |
| Stop all monitoring | `Close()` | `void` |
| Release the client | `Dispose()` | `void` |

## Runtime footprint

The SDK uses:

- `NSec.Cryptography` `25.4.0` for Ed25519 key loading and signing.
- `System.Net.Http` for HTTPS requests.
- `System.Text.Json` for JSON.
- .NET's built-in AES-GCM and HKDF implementations for the optional cache.

No external HTTP or JSON package is required.

## Documentation

- [SikkerKey documentation](https://docs.sikkerkey.com)
- [SDK overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [.NET SDK reference](https://docs.sikkerkey.com/docs/sdk/dotnet)
- [Machine authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

The SikkerKey .NET SDK is available under the [MIT License](LICENSE).

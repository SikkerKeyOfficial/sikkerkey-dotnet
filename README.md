# SikkerKey .NET SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0+-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com)
[![C#](https://img.shields.io/badge/C%23-12-239120?logo=csharp&logoColor=white)](https://learn.microsoft.com/en-us/dotnet/csharp/)

The official .NET SDK for [SikkerKey](https://sikkerkey.com). Read-only access to secrets using Ed25519 machine authentication. Single dependency: `NSec.Cryptography` for Ed25519 signing. Runs on persistent hosts (identity on disk) and serverless or ephemeral environments (in-memory bootstrap).

## Installation

```bash
dotnet add package SikkerKey
```

Requires .NET 8.0+.

## Quick Start

```csharp
using SikkerKey;

var sk = SikkerKeyClient.Create("vault_abc123");
var apiKey = await sk.GetSecretAsync("sk_stripe_key");
```

The SDK reads the machine identity from `~/.sikkerkey/vaults/<vault-id>/identity.json`, signs every request with the machine's Ed25519 private key, and returns the decrypted value.

## Client Creation

```csharp
// Explicit vault ID
var sk = SikkerKeyClient.Create("vault_abc123");

// Direct path to identity file
var sk = SikkerKeyClient.Create("/etc/sikkerkey/vaults/vault_abc123/identity.json");

// Auto-detect from SIKKERKEY_IDENTITY env or single vault on disk
var sk = SikkerKeyClient.Create();
```

Throws `ConfigurationException` if the identity is missing, the key can't be loaded, or multiple vaults exist without a specified vault ID.

## Serverless (In-Memory Bootstrap)

On a long-lived host the SDK loads a persistent identity from disk. Serverless and other ephemeral or read-only-filesystem environments (AWS Lambda, Google Cloud Run, Fly.io, and similar) have no identity to persist. `BootstrapInMemoryAsync` handles that case: it generates an Ed25519 keypair in memory, registers an ephemeral machine with an enrollment token, and returns a ready client. Nothing is written to disk.

```csharp
var sk = await SikkerKeyClient.BootstrapInMemoryAsync(
    Environment.GetEnvironmentVariable("SIKKERKEY_VAULT_ID")!,
    Environment.GetEnvironmentVariable("SIKKERKEY_ENROLLMENT_TOKEN")!
);

var dbUrl = await sk.GetSecretAsync("sk_db_prod");
```

Create an enrollment token in the dashboard and supply its plaintext plus your vault ID. The token only registers an ephemeral machine scoped to the policy you set (projects, secrets, lifetime); it cannot read secrets on its own.

Enrollment happens once, in the `BootstrapInMemoryAsync` call. The returned `SikkerKeyClient` then behaves exactly like one from `Create`: it signs each read with the in-memory key. The private key is gone when the process exits. The ephemeral machine lives for the lifetime set on the token; reading after it expires throws `AuthenticationException`, so size the token's machine lifetime to your workload. The common path is to read secrets at startup and hold the values.

### Options

```csharp
var sk = await SikkerKeyClient.BootstrapInMemoryAsync(
    vaultId,
    token,
    hostname: "worker-1",   // defaults to $HOSTNAME, then "serverless"
    name: "batch-runner"    // overridden if the token defines a name pattern
);
```

### Provisioning the Token

When you create the enrollment token for a serverless or ephemeral deployment:

- Set a short machine lifetime (minutes). Each cold start mints a fresh ephemeral machine, and short-lived ones free their slot quickly as they expire.
- Set max-uses high enough for your cold-start and concurrency volume.
- Leave the source-CIDR restriction unset, since serverless egress IPs are dynamic.
- If the vault has an IP allowlist, make sure it permits the platform's egress or leave it off.
- Set a name pattern on the token (for example `worker-{uuid8}`) so each machine gets a unique name. A name pattern takes precedence over `name`.

Each live ephemeral machine counts against your plan's machine limit until it expires.

## Reading Secrets

### Single Value

```csharp
var apiKey = await sk.GetSecretAsync("sk_stripe_prod");
```

### Structured (Multiple Fields)

```csharp
var fields = await sk.GetFieldsAsync("sk_db_prod");
var host = fields["host"];       // "db.example.com"
var password = fields["password"]; // "hunter2"
```

Throws `SecretStructureException` if the secret value is not a JSON object.

### Single Field

```csharp
var password = await sk.GetFieldAsync("sk_db_prod", "password");
```

Throws `FieldNotFoundException` if the field doesn't exist. The error message includes available field names.

## Listing Secrets

```csharp
// All secrets this machine can access
var secrets = await sk.ListSecretsAsync();
foreach (var s in secrets)
    Console.WriteLine($"{s.Id}: {s.Name}");

// Secrets in a specific project
var projectSecrets = await sk.ListSecretsByProjectAsync("proj_production");
```

Returns `List<SecretListItem>` with `Id`, `Name`, `FieldNames` (nullable), and `ProjectId` (nullable).

## Export

```csharp
// All secrets as a flat dictionary
var env = await sk.ExportAsync();
// {"API_KEY": "sk-live-...", "DB_CREDS_HOST": "db.example.com"}

// Scoped to a project
var env = await sk.ExportAsync("proj_production");

// Inject into environment
foreach (var (key, value) in await sk.ExportAsync())
    Environment.SetEnvironmentVariable(key, value);
```

Structured secrets are flattened: `SECRET_NAME_FIELD_NAME`.

## Watching for Changes

Watch secrets for real-time updates. When a secret is rotated, updated, or deleted, the callback fires with the new value. Polling happens on a background task - your application is never blocked.

```csharp
sk.Watch("sk_db_password", (e) =>
{
    switch (e.Status)
    {
        case WatchStatus.Changed:
            Console.WriteLine($"New value: {e.Value}");
            // Structured secrets include parsed fields
            if (e.Fields != null)
                Console.WriteLine($"Fields: {string.Join(", ", e.Fields)}");
            break;
        case WatchStatus.Deleted:
            Console.WriteLine("Secret was deleted");
            break;
        case WatchStatus.AccessDenied:
            Console.WriteLine("Access revoked");
            break;
        case WatchStatus.Error:
            Console.WriteLine($"Error: {e.Error}");
            break;
    }
});
```

### Practical Example

```csharp
// Auto-rotate database credentials
sk.Watch("sk_db_credentials", (e) =>
{
    if (e.Status == WatchStatus.Changed)
    {
        Database.ConfigureCredentials(e.Fields!["username"], e.Fields["password"]);
    }
});
```

### Poll Interval

The default poll interval is 15 seconds. The server enforces a minimum of 10 seconds.

```csharp
sk.SetPollInterval(30); // seconds
```

### Stop Watching

```csharp
// Stop watching a specific secret
sk.Unwatch("sk_db_password");

// Stop all watches and shut down polling
sk.Close();
```

`SikkerKeyClient` implements `IDisposable`:

```csharp
using var sk = SikkerKeyClient.Create("vault_abc123");
sk.Watch("sk_api_key", OnChange);
// Automatically disposed on scope exit
```

## Multi-Vault

```csharp
var prod = SikkerKeyClient.Create("vault_a1b2c3");
var staging = SikkerKeyClient.Create("vault_x9y8z7");

var prodKey = await prod.GetSecretAsync("sk_api_key");
var stagingKey = await staging.GetSecretAsync("sk_api_key");
```

### List Registered Vaults

```csharp
var vaults = SikkerKeyClient.ListVaults();
// ["vault_a1b2c3", "vault_x9y8z7"]
```

Static method, synchronous.

## Machine Info

```csharp
sk.MachineId    // "550e8400-e29b-41d4-a716-446655440000"
sk.MachineName  // "api-server-1"
sk.VaultId      // "vault_abc123"
sk.ApiUrl       // "https://api.sikkerkey.com"
```

## Error Handling

```csharp
using SikkerKey;

try
{
    var secret = await sk.GetSecretAsync("sk_nonexistent");
}
catch (NotFoundException)
{
    // Secret doesn't exist
}
catch (AccessDeniedException)
{
    // Machine not approved or no grant
}
catch (AuthenticationException)
{
    // Invalid signature or unknown machine
}
catch (ApiException e)
{
    // Any other HTTP error
    Console.WriteLine(e.HttpStatus);
}
```

### Exception Hierarchy

```
SikkerKeyException
├── ConfigurationException      - identity/key issues
├── SecretStructureException    - secret is not a JSON object (GetFieldsAsync)
├── FieldNotFoundException      - field not in structured secret (GetFieldAsync)
└── ApiException                - HTTP error (has HttpStatus property)
    ├── AuthenticationException - 401
    ├── AccessDeniedException   - 403
    ├── NotFoundException       - 404
    ├── ConflictException       - 409
    ├── RateLimitedException    - 429
    └── ServerSealedException   - 503
```

## Identity Resolution

1. **Explicit path** - starts with `/` or contains `identity.json`
2. **Vault ID** - looks up `~/.sikkerkey/vaults/{vaultId}/identity.json`
3. **`SIKKERKEY_IDENTITY` env** - path to identity file
4. **Auto-detect** - single vault on disk

The `vault_` prefix is added automatically if not present. Override base directory with `SIKKERKEY_HOME`.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SIKKERKEY_IDENTITY` | Path to `identity.json` - overrides vault lookup |
| `SIKKERKEY_HOME` | Base config directory (default: `~/.sikkerkey`) |

## Retry Behavior

429 and 503 responses are retried up to 3 times with exponential backoff (1s, 2s, 4s). Each retry uses a fresh timestamp and nonce. Network errors (`HttpRequestException`, `TaskCanceledException`) are also retried.

## Authentication

Every request includes Ed25519-signed headers: `X-Machine-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`. HTTPS enforced for non-localhost. 15-second request timeout.

## Method Reference

| Method | Returns | Description |
|--------|---------|-------------|
| `SikkerKeyClient.Create(vaultOrPath?)` | `SikkerKeyClient` | Create client (static, sync) |
| `SikkerKeyClient.BootstrapInMemoryAsync(vaultId, token, hostname?, name?)` | `Task<SikkerKeyClient>` | Memory-only serverless bootstrap (static) |
| `SikkerKeyClient.ListVaults()` | `List<string>` | List registered vault IDs (static) |
| `GetSecretAsync(secretId)` | `Task<string>` | Read a secret value |
| `GetFieldsAsync(secretId)` | `Task<Dictionary<string, string>>` | Read structured secret |
| `GetFieldAsync(secretId, field)` | `Task<string>` | Read single field |
| `ListSecretsAsync()` | `Task<List<SecretListItem>>` | List all accessible secrets |
| `ListSecretsByProjectAsync(projectId)` | `Task<List<SecretListItem>>` | List secrets in a project |
| `ExportAsync(projectId?)` | `Task<Dictionary<string, string>>` | Export as env map |
| `Watch(secretId, callback)` | `void` | Watch a secret for changes |
| `Unwatch(secretId)` | `void` | Stop watching a secret |
| `SetPollInterval(seconds)` | `void` | Set poll interval (min 10s) |
| `Close()` | `void` | Stop all watches, shut down polling |

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `NSec.Cryptography` | >=25.4.0 | Ed25519 key loading and signing |

All other functionality uses .NET built-ins: `System.Net.Http`, `System.Text.Json`, `System.Security.Cryptography`.

## Documentation

- [SDK Overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [.NET SDK Reference](https://docs.sikkerkey.com/docs/sdk/dotnet)
- [Machine Authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

MIT - see [LICENSE](LICENSE) for details.

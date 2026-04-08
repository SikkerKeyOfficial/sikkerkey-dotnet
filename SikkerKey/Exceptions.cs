namespace SikkerKey;

/// <summary>Base exception for all SikkerKey SDK errors.</summary>
public class SikkerKeyException : Exception
{
    public SikkerKeyException(string message) : base(message) { }
    public SikkerKeyException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Identity file missing, malformed, or private key not found.</summary>
public class ConfigurationException : SikkerKeyException
{
    public ConfigurationException(string message) : base(message) { }
    public ConfigurationException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>HTTP error from the SikkerKey API.</summary>
public class ApiException : SikkerKeyException
{
    public int HttpStatus { get; }
    public ApiException(string message, int httpStatus = 0) : base(message) => HttpStatus = httpStatus;
}

/// <summary>401 — signature verification failed or machine unknown.</summary>
public class AuthenticationException : ApiException
{
    public AuthenticationException(string message) : base(message, 401) { }
}

/// <summary>403 — machine not approved, disabled, or no access grant.</summary>
public class AccessDeniedException : ApiException
{
    public AccessDeniedException(string message) : base(message, 403) { }
}

/// <summary>404 — secret or resource not found.</summary>
public class NotFoundException : ApiException
{
    public NotFoundException(string message) : base(message, 404) { }
}

/// <summary>409 — conflict (e.g. cannot rotate dynamic secret).</summary>
public class ConflictException : ApiException
{
    public ConflictException(string message) : base(message, 409) { }
}

/// <summary>429 — too many requests.</summary>
public class RateLimitedException : ApiException
{
    public RateLimitedException(string message) : base(message, 429) { }
}

/// <summary>503 — server is sealed, awaiting unseal.</summary>
public class ServerSealedException : ApiException
{
    public ServerSealedException(string message) : base(message, 503) { }
}

/// <summary>Wrong secret type for the operation.</summary>
public class SecretStructureException : SikkerKeyException
{
    public SecretStructureException(string message) : base(message) { }
}

/// <summary>Field not found in a structured secret.</summary>
public class FieldNotFoundException : SikkerKeyException
{
    public FieldNotFoundException(string message) : base(message) { }
}

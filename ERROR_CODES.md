# MagicRune Error Code Reference

## Overview

MagicRune uses a structured error code system to provide clear and actionable error information. Each error has a unique code, category, and recommended retry strategy.

## Error Code Format

Error codes follow the pattern: `MR-XXXX`
- `MR` - MagicRune prefix
- `XXXX` - 4-digit numeric code

## Error Categories

### 1000-1999: Input/Request Errors
| Code | Description | Retry Strategy | HTTP Equivalent |
|------|-------------|----------------|-----------------|
| MR-1001 | Invalid JSON in request | No retry | 400 |
| MR-1002 | Missing required field | No retry | 400 |
| MR-1003 | Schema validation failed | No retry | 400 |
| MR-1004 | Invalid command syntax | No retry | 400 |
| MR-1005 | File not found | No retry | 404 |
| MR-1006 | Invalid seed value | No retry | 400 |

### 2000-2999: Policy/Security Errors
| Code | Description | Retry Strategy | HTTP Equivalent |
|------|-------------|----------------|-----------------|
| MR-2001 | Network access denied by policy | No retry | 403 |
| MR-2002 | File system access denied by policy | No retry | 403 |
| MR-2003 | Command blocked by risk assessment | No retry | 403 |
| MR-2004 | Policy file not found | No retry | 404 |
| MR-2005 | Invalid policy format | No retry | 400 |
| MR-2006 | Risk score exceeds threshold | No retry | 403 |

### 3000-3999: Execution/Sandbox Errors
| Code | Description | Retry Strategy | HTTP Equivalent |
|------|-------------|----------------|-----------------|
| MR-3001 | Sandbox initialization failed | Retry with backoff | 500 |
| MR-3002 | Process exceeded time limit | No retry | 408 |
| MR-3003 | Process exceeded memory limit | No retry | 413 |
| MR-3004 | Process exceeded CPU limit | No retry | 429 |
| MR-3005 | Too many processes spawned | No retry | 429 |
| MR-3006 | Sandbox isolation breach attempted | No retry | 403 |
| MR-3007 | WASM execution error | Retry once | 500 |
| MR-3008 | Native sandbox unavailable | Fallback to WASM | 503 |

### 4000-4999: System/Infrastructure Errors
| Code | Description | Retry Strategy | HTTP Equivalent |
|------|-------------|----------------|-----------------|
| MR-4001 | NATS connection failed | Retry with backoff | 503 |
| MR-4002 | JetStream publish failed | Retry with backoff | 503 |
| MR-4003 | Message deduplication detected | No retry (success) | 200 |
| MR-4004 | Ledger storage error | Retry once | 500 |
| MR-4005 | Temporary file creation failed | Retry once | 500 |
| MR-4006 | System resource exhausted | Retry after delay | 503 |

### 5000-5999: Internal Errors
| Code | Description | Retry Strategy | HTTP Equivalent |
|------|-------------|----------------|-----------------|
| MR-5001 | Unexpected internal error | Contact support | 500 |
| MR-5002 | Assertion failed | Contact support | 500 |
| MR-5003 | Unimplemented feature | No retry | 501 |

## Exit Codes

MagicRune CLI uses the following exit codes:

| Exit Code | Meaning | Error Code Range |
|-----------|---------|------------------|
| 0 | Success | - |
| 1 | General error | 5000-5999 |
| 2 | Input/request error | 1000-1999 |
| 3 | Policy violation | 2000-2999 |
| 20 | Timeout | MR-3002 |
| 101 | Test failure | - |

## Retry Strategies

### No Retry
Client errors that won't be resolved by retrying. Fix the request and try again.

### Retry Once
Transient errors that might resolve immediately. Retry once after 1 second.

### Retry with Backoff
Infrastructure errors that typically resolve within minutes. Use exponential backoff:
- 1st retry: 1 second
- 2nd retry: 2 seconds
- 3rd retry: 4 seconds
- Maximum 3 retries

### Retry After Delay
Resource exhaustion errors. Wait at least 30 seconds before retrying.

### Fallback to WASM
When native sandbox is unavailable, automatically fallback to WASM sandbox.

### Contact Support
Unexpected errors requiring investigation. Include error code and context in support request.

## Error Response Format

```json
{
  "error": {
    "code": "MR-2001",
    "message": "Network access to example.com denied by policy",
    "category": "policy",
    "retry": false,
    "details": {
      "requested_host": "example.com",
      "policy_id": "default"
    }
  }
}
```

## Logging

All errors are logged with structured fields:
- `error_code`: The MR-XXXX code
- `category`: Error category name
- `retry_strategy`: Recommended retry approach
- `context`: Additional debugging information

Example log entry:
```
level=error error_code=MR-2001 category=policy retry_strategy=no_retry 
message="Network access denied" host=example.com policy=default
```
# Examples

Implementations built on top of **api-pii**. Each example shows a real use case
where sensitive data must never reach the LLM in plain form.

All examples assume api-pii is running at `http://localhost:8000`.
The anonymization/de-anonymization is completely transparent — the examples
just talk to the proxy as if it were the Claude API directly.

## Available

| Example | Description |
|---|---|
| [`document_summary/`](document_summary/) | Upload a PDF, DOCX or TXT — get a summary with real data restored |

## Ideas for future examples

| Use case | What gets protected |
|---|---|
| Server log analyzer | IPs → 127.0.0.x, hostnames |
| Code reviewer | Tokens, passwords, IPs hardcoded in source |
| Contract translator | Names, companies, ID numbers |
| Nessus / OpenVAS report parser | IPs, hostnames, ports |
| Slack / email thread summarizer | Names, emails, internal hostnames |

## How to add a new example

1. Create a folder under `examples/`
2. Point your SDK or HTTP client at `http://localhost:8000` instead of `https://api.anthropic.com`
3. Use `x-session-id` header to keep mappings consistent across requests in the same session
4. That's it — api-pii handles the rest transparently

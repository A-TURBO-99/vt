# vt

VirusTotal domain reconnaissance CLI.

`vt` queries the VirusTotal Domain Report API for one or more domains, extracts URLs and/or subdomains, removes duplicates, prints results for pipelines, and can save them to a file.

Author: **A-TURBO-99**

## Requirements

- Go 1.21 or later
- A VirusTotal API key (v2)

## Install

```bash
git clone https://github.com/A-TURBO-99/vt.git
cd vt
go build -o vt ./cmd/vt
```

Optional:

```bash
go install github.com/A-TURBO-99/vt/cmd/vt@latest
cp ~/go/bin/vt /usr/local/bin;
```

## Configuration

API keys are **not** passed on the command line.

```bash
cp config/config.json.example config/config.json
```

`config/config.json`:

```json
{
  "api_key_1": "YOUR_PRIMARY_API_KEY",
  "api_key_2": "YOUR_FALLBACK_API_KEY"
}
```

Behavior:

1. Requests always use `api_key_1` first.
2. If the primary key fails because of an API-key, authentication, rate-limit, or quota problem, `vt` retries with `api_key_2`.
3. Leave `api_key_2` empty to use only the primary key.
4. API keys are never printed to stdout, stderr, logs, or error messages.

The tool looks for `config/config.json` in the current working directory and next to the binary.

## Usage

```text
vt -d <domain>  -u|-s|-a  [-o file] [-t n]
vt -l <file>    -u|-s|-a  [-o file] [-t n]
```

Flags:

| Flag | Description |
|------|-------------|
| `-d` | Single domain or subdomain |
| `-l` | File with one domain per line |
| `-u` | Extract URLs |
| `-s` | Extract subdomains |
| `-a` | Extract URLs and subdomains |
| `-o` | Save results to a file |
| `-t` | Number of threads (default `1`) |
| `-c` | Path to `config.json` (optional) |
| `-h` | Show help |

Use exactly one of `-d` or `-l`, and exactly one of `-u`, `-s`, or `-a`.

## Examples

Single domain, URLs:

```bash
vt -d example.com -u
```

Single domain, subdomains:

```bash
vt -d example.com -s
```

Single domain, everything:

```bash
vt -d example.com -a
```

Input file, URLs:

```bash
vt -l domains.txt -u
```

Input file, subdomains:

```bash
vt -l domains.txt -s
```

Save URLs:

```bash
vt -d example.com -u -o urls.txt
```

Save subdomains:

```bash
vt -d example.com -s -o subdomains.txt
```

Pipeline:

```bash
vt -d example.com -u | sort -u
```

Input file with pipeline:

```bash
vt -l domains.txt -s | sort -u
```

Multiple threads:

```bash
vt -l domains.txt -u -t 5
```

Default is **1 thread** and **1 request per second**. Use `-t` to run more workers in parallel.

## Output

Status messages (banner, `[+] Processing...`, `[+] Found...`, errors) go to **stderr**.

Extracted results go to **stdout**, one per line, with no prefixes. That keeps pipelines clean:

```bash
vt -d example.com -u | sort -u
```

Example (`-u`):

```text
[+] Processing: example.com
[+] Found 25 URLs

https://example.com/
https://example.com/blog/
https://example.com/api/
```

Example (`-s`):

```text
[+] Processing: example.com
[+] Found 12 Subdomains

api.example.com
app.example.com
blog.example.com
```

Example (`-a`):

```text
[+] Processing: example.com
[+] Found 25 URLs
[+] Found 12 Subdomains

https://example.com/
https://example.com/blog/

api.example.com
app.example.com
```

## Extraction

URLs are taken from both VirusTotal fields:

- `detected_urls[].url`
- `undetected_urls[][0]` (first element of each inner array)

Subdomains are taken from `subdomains[]`.

Missing fields are treated as empty. Duplicates are removed while preserving first-seen order, including across multiple input targets.

## Input files

`-l` reads one domain per line.

- Empty lines are ignored
- Surrounding whitespace is trimmed
- Duplicate targets are skipped

## Project layout

```text
cmd/vt/              entrypoint
internal/cli/        flags and run loop
internal/config/     API key file
internal/vtapi/      VirusTotal HTTP client
internal/extract/    JSON parsing and extraction
internal/input/      domain and file loading
internal/output/     stdout / stderr / -o
internal/unique/     order-preserving dedupe
internal/banner/     startup banner
config/              API key configuration
```

## Tests

```bash
go test ./...
```

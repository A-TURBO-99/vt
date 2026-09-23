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
```

## Configuration

API keys are **not** passed on the command line.

Copy the example file and edit it:

```bash
cp config/config.json.example config/config.json
```

`config/config.json`:

```json
{
  "api_key_1": "YOUR_API_KEY_1",
  "api_key_2": "YOUR_API_KEY_2",
  "api_key_3": "YOUR_API_KEY_3",
  "api_key_4": "YOUR_API_KEY_4",
  "api_key_5": "YOUR_API_KEY_5"
}
```

Behavior:

1. Requests use `api_key_1` until VirusTotal returns a rate-limit or quota error.
2. Then `vt` switches to `api_key_2` and keeps using it until that key is also limited.
3. The same happens for `api_key_3`, `api_key_4`, and `api_key_5`.
4. Empty or placeholder slots are skipped. You can fill only the keys you have.
5. Invalid keys are skipped and the next configured key is used.
6. API keys are never printed to stdout, stderr, logs, or error messages.

The tool looks for `config/config.json` in the current working directory and next to the binary.

## Usage

```text
vt -d <domain>  -u|-s|-a  [-o file] [-t n] [-dl seconds]
vt -l <file>    -u|-s|-a  [-o file] [-t n] [-dl seconds]
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
| `-dl` | Delay in seconds between requests (default `1`, `0` disables) |
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

Delay between requests:

```bash
vt -l domains.txt -u -dl 2
```

Fractional delays are allowed:

```bash
vt -l domains.txt -u -t 5 -dl 0.5
```

Defaults are **1 thread** and a **1 second delay** between requests. Use `-t` to run more workers in parallel and `-dl` to change the spacing (`-dl 0` disables the delay).

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

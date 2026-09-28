<img width="349" height="365" alt="EaseUS_2026_09_28_14_30_17" src="https://github.com/user-attachments/assets/3a7b9f3a-b078-40c0-8244-c6213bc9f685" />

# vt

VirusTotal domain and IP reconnaissance CLI.

`vt` queries the VirusTotal Domain Report and IP Address Report APIs for one or more targets, extracts URLs and/or subdomains, removes duplicates, prints results for pipelines, and can save them to a file.

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
cp ~/go/bin/vt /usr/local/bin
```

## Configuration

API keys are **not** passed on the command line.

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
vt -ip <ip>     -u|-s|-a  [-o file] [-t n] [-dl seconds]
vt -l <file>    -u|-s|-a  [-o file] [-t n] [-dl seconds]
```

Flags:

| Flag | Description |
|------|-------------|
| `-d` | "domain" Single domain or subdomain |
| `-ip` | "IP" Single IPv4 address |
| `-l` | "list" File with one domain or IPv4 address per line |
| `-u` | "URLS" Extract URLs |
| `-s` | "Subdomains" Extract subdomains (or resolved hostnames for IPs) |
| `-a` | "All" Extract URLs and subdomains |
| `-o` | Save results to a file |
| `-t` | Number of threads (default `1`) |
| `-dl` | Delay in seconds between requests (default `1`, `0` disables) |
| `-c` | Path to `config.json` (optional) |
| `-h` | Show help |

Use exactly one of `-d`, `-ip`, or `-l`, and exactly one of `-u`, `-s`, or `-a`.

## Examples

Single domain &&  Collect URLs or Subdomains or ALL:

```bash
vt -d example.com -u
vt -d example.com -s
vt -d example.com -a
```

Single IP &&  Collect URLs, resolved hostnames, or ALL:

```bash
vt -ip 8.8.8.8 -u
vt -ip 8.8.8.8 -s
vt -ip 8.8.8.8 -a
```

`-u` extracts URLs from `detected_urls` and `undetected_urls`.
`-s` extracts hostnames from `resolutions[].hostname`.
`-a` extracts both.

Input file, URLs:

```bash
vt -l domains.txt -u
vt -l domains.txt -s
vt -l domains.txt -a
```

The file may contain domains, IPv4 addresses, or a mixture of both. Each line is classified independently and sent to the matching VirusTotal endpoint:

```text
example.com        -> Domain Report API
8.8.8.8            -> IP Address Report API
api.example.com    -> Domain Report API
1.1.1.1            -> IP Address Report API
```

Empty lines and comments (`#`) are ignored. The same `-u`, `-s`, and `-a` extraction modes apply to both domains and IPs.

Save subdomains:

```bash
vt -d example.com -s -o subdomains.txt
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



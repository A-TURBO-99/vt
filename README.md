<img width="348" height="364" alt="EaseUS_2026_09_28_16_14_36" src="https://github.com/user-attachments/assets/b411e1d1-69d3-4a31-9d39-42360f6989d2" />


# vt

VirusTotal domain and IP reconnaissance CLI.

`vt` queries the VirusTotal Domain Report and IP Address Report APIs for one or more targets, extracts URLs, subdomains, or IP addresses, removes duplicates, prints results for pipelines, and can save them to a file.

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

`config/config.json` supports a dynamic `api_keys` array. Add as many keys as you need; there is no fixed limit:

```json
{
  "api_keys": [
    "YOUR_API_KEY_1",
    "YOUR_API_KEY_2",
    "YOUR_API_KEY_3"
  ]
}
```

The legacy `api_key_1` through `api_key_10` format is still supported for existing configurations. When both formats are present, keys in `api_keys` are used first, followed by legacy keys. Empty values, placeholders, and duplicates are ignored.

Behavior:

1. Requests start with the first configured API key.
2. On a rate-limit or quota error, `vt` switches to the next available key.
3. After the last available key is rate-limited, rotation wraps around and reuses the first available key.
4. Invalid/rejected keys are skipped permanently for the current run; quota-limited keys remain in the rotation.
5. If every key is quota-limited, the tool keeps cycling until a request succeeds or the run is interrupted (for example, with Ctrl+C). If every key is invalid/rejected, the request stops with an error.
6. The `-dl` delay is applied to retries as well as new targets.
7. API keys are never printed to stdout, stderr, logs, or error messages.
8. The local `config/config.json` is ignored by Git so credentials are not committed accidentally.

Copy `config/config.json.example` to `config/config.json`, then fill in the keys you have. Keep `config/config.json` private and do not commit it to Git.

The tool looks for `config/config.json` in the current working directory and next to the binary.

## Usage

```text
vt -d <domain>  -u|-s|-ips  [-o file] [-t n] [-dl seconds] [-tm seconds]
vt -ip <ip>     -u|-s|-ips  [-o file] [-t n] [-dl seconds] [-tm seconds]
vt -l <file>    -u|-s|-ips  [-o file] [-t n] [-dl seconds] [-tm seconds]
```

Flags:

| Flag | Description |
|------|-------------|
| `-d` | "domain" Single domain or subdomain |
| `-ip` | "IP" Single IPv4 address |
| `-l` | "list" File with one domain or IPv4 address per line |
| `-u` | "URLS" Extract URLs |
| `-s` | "Subdomains" Extract subdomains (or resolved hostnames for IPs) |
| `-ips` | Extract IP addresses |
| `-o` | Save results to a file |
| `-t` | Number of threads (default `1`) |
| `-dl` | Delay in seconds between requests (default `1`, `0` disables) |
| `-tm` | HTTP request timeout in seconds (default `6`) |
| `-c` | Path to `config.json` (optional) |
| `-h` | Show help |

Use exactly one of `-d`, `-ip`, or `-l`, and exactly one of `-u`, `-s`, or `-ips`.

## Examples

Single domain &&  Collect URLs, Subdomains, or IPs:

```bash
vt -d example.com -u
vt -d example.com -s
vt -d example.com -ips
```

Single IP &&  Collect URLs, resolved hostnames, or IPs:

```bash
vt -ip 8.8.8.8 -u
vt -ip 8.8.8.8 -s
vt -ip 8.8.8.8 -ips
```

`-u` extracts URLs from `detected_urls` and `undetected_urls`.
`-s` extracts hostnames from `resolutions[].hostname`.
`-ips` extracts IP addresses from `resolutions[].ip_address`.

Input file:

```bash
vt -l domains.txt -u
vt -l domains.txt -s
vt -l domains.txt -ips
```

The file may contain domains, IPv4 addresses, or a mixture of both. Each line is classified independently and sent to the matching VirusTotal endpoint:

```text
example.com        -> Domain Report API
8.8.8.8            -> IP Address Report API
api.example.com    -> Domain Report API
1.1.1.1            -> IP Address Report API
```

Empty lines and comments (`#`) are ignored. The same `-u`, `-s`, and `-ips` extraction modes apply to both domains and IPs.

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

HTTP request timeout:

```bash
vt -d example.com -u -tm 10
vt -ip 8.8.8.8 -s -tm 3
vt -l targets.txt -u -dl 2 -tm 6
```

`-dl` is the delay between requests. `-tm` is how long each HTTP request may wait before timing out.

Defaults are **1 thread**, a **1 second delay** between requests, and a **6 second** HTTP timeout. Use `-t` to run more workers in parallel, `-dl` to change the spacing (`-dl 0` disables the delay), and `-tm` to change the request timeout.



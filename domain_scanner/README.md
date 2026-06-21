# Domain Scanner

Enumerates every **2-letter and 3-letter** label (`a–z` by default, optionally
`0–9`) and checks whether the domain is **registered or available** for the
`.sh`, `.ac` and `.cool` TLDs. Available (unregistered) domains are written to
disk.

## How it detects availability

| TLD          | Method | Signal |
|--------------|--------|--------|
| `.cool`      | RDAP over HTTPS (authoritative); `--method doh` for speed | HTTP `404` = available, `200` = registered |
| `.sh`, `.ac` | WHOIS port 43 (authoritative); auto-falls back to DNS-over-HTTPS when port 43 is blocked | WHOIS "not registered" markers, or DoH `NXDOMAIN`/no-NS = available |

> **Note on the DoH fallback:** `.sh`/`.ac` have no public RDAP service, so the
> authoritative check is WHOIS on TCP port 43. Many cloud/sandbox networks block
> port 43 and only allow HTTPS — in that case the scanner falls back to a
> DNS-over-HTTPS heuristic (a domain with no NS delegation is treated as
> available). This is a *heuristic*: a registered-but-undelegated domain could
> be misreported as available. **Run on an unrestricted network (or pass
> `--method whois`) for authoritative `.sh`/`.ac` results.**

## Usage

```bash
# everything: 2+3 letter, all three TLDs -> ./results/
python domain_scanner.py

# only two-letter .cool, 40 workers
python domain_scanner.py --tld cool --lengths 2 --workers 40

# include digits (0-9 a-z)
python domain_scanner.py --charset alnum

# force authoritative WHOIS for .sh/.ac (needs port 43 open)
python domain_scanner.py --tld sh --method whois
```

### Key options

- `--tld {sh,ac,cool,all}` (default `all`)
- `--lengths 2,3` comma list of label lengths
- `--charset {alpha,alnum,digit}` `alpha`=a–z (default)
- `--workers N` concurrent workers per TLD (default 20)
- `--method {auto,whois,doh}` detection method for `.sh`/`.ac` (`.cool` always RDAP)
- `--throttle SECONDS` politeness delay before each request
- `--outdir DIR` output directory (default `./results`)

## Output (resumable)

- `results/available_<tld>.txt` — one available domain per line (streamed live)
- `results/checked_<tld>.csv` — `domain,status,method,detail` for every label

Re-running skips labels already present in the CSV, so an interrupted scan
resumes where it left off.

## Search space

`a–z` only: 676 two-letter + 17,576 three-letter = 18,252 labels per TLD.
Adding digits (`alnum`) grows this to 1,296 + 46,656 = 47,952 per TLD.

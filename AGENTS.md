# Contributing guide for AI agents

## Project purpose

This is a local-only CLI for a user-owned TP-Link XGB430v Pro ESDIGI router.
It logs in, derives the firmware-published backup filename, downloads the
backup into memory, decrypts and verifies it, then prints Admin, PPPoE, and
SIP credential pairs. It is deliberately firmware-specific and must fail
closed for unknown protocols or formats.

## Repository layout

```text
cmd/digi-credentials/   Process entry point only.
pkg/digicredentials/    Application implementation and unit tests.
build/                  Build-related documentation/assets.
docs/                   Architecture documentation.
```

Keep `cmd/digi-credentials/main.go` minimal. New implementation belongs in
`pkg/digicredentials`, grouped by concern:

- `transport.go`: direct-IP HTTP(S), origin containment, cookies, and TLS.
- `session.go`: AES-CBC, RSA no-padding signing, and session encryption.
- `router_client.go`: protocol validation, login, metadata reads, backup path.
- `crypto_backup.go`: DES, MD5 verification, and bounded LZSS decoding.
- `config.go`: TP-Link XML dialect parsing and credential selection.
- `debug.go`: safe operational diagnostics only.

## Toolchain and routine commands

Go is pinned in `mise.toml`; use Mise rather than a system Go version.

```sh
mise install
make test
make vet
make check
make build
./bin/digi-credentials --debug
```

The Makefile keeps Go's cache under `.cache/`, which is ignored. Generated
binaries go in `bin/`, which is also ignored. Do not commit either directory.

## Safety requirements

Treat router data and credentials as secrets.

- Never print, log, commit, or persist passwords, usernames, cookies, tokens,
  encrypted request bodies, backup bytes, XML, or extracted credentials.
- `.env.local` is ignored and may contain `USERNAME` and `PASSWORD`. Do not
  read its values into tool output. Do not add application support for loading
  credentials from environment variables; the interactive CLI must keep hidden
  terminal password entry.
- `--debug` must output only safe metadata: method, path, status, byte counts,
  and protocol decisions. Preserve this redaction boundary in all new logs.
- The client must contact only the numeric IP supplied by the user. Preserve
  the no-proxy, no-DNS, no-redirect, same-origin, standard-port, and response-
  size protections in `transport.go`.
- Never execute JavaScript served by the router. It is inspected as text only.
- Do not save router backups or configuration XML, including in tests or `/tmp`.

## Protocol constraints to preserve

- Validate the observed AES-CBC/RSA login protocol before sending credentials.
- RSA signing is intentionally no-padding to match this router firmware.
- Backup names are derived only after validating the JavaScript formula and
  querying the whitelisted read-only objects `DEV2_DEV_INFO` and
  `DEV2_SYS_CFG`. Never probe or guess backup filenames.
- DES-decrypted backups require MD5 verification before LZSS decompression or
  output.
- LZSS output is capped by `maxXML`. This firmware can encode a final implicit
  one-byte sentinel: accept it only at EOF and only when the resulting data
  passes the XML signature checks.
- The TP-Link configuration dialect can contain unquoted `val=` attributes.
  Reject DTDs/entities and do not use unsafe XML expansion.
- If similarly ranked records disagree, output `(varios)` rather than choosing
  one. Do not infer SIP credentials outside an explicit voice/SIP context.

## Testing

Keep unit tests offline and under `pkg/digicredentials`. Cover malformed input
and rejection paths in addition to success paths.

For an explicitly user-authorized live test, create a temporary test that:

1. Reads `.env.local` in memory only.
2. Uses the router IP authorized by the user.
3. Performs prepare, login, download, decrypt, parse, and logout.
4. Never logs secret values or writes backup/XML data.
5. Is removed immediately after the run.

The last live validation against `192.168.11.254` successfully completed login,
dynamic backup path derivation, download, DES/MD5/LZSS processing, XML parsing,
credential-record discovery, and logout.

## Change checklist

Before finishing a change:

1. Run `gofmt` on changed Go files.
2. Run `make check` and `make build`.
3. Confirm `.env.local`, `.cache/`, and `bin/` are ignored.
4. Update `README.md` or `docs/architecture.md` for user-facing or structural
   changes.
5. Preserve GPL-3.0-or-later notices and attributions.

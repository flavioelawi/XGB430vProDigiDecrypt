# TP-Link XGB430v Pro ESDIGI credential reader

An interactive, local-only CLI for reading credentials from a backup made by a
TP-Link XGB430v Pro ESDIGI router you own.

This Go implementation contacts only the numeric IP entered at the prompt. It
does not use DNS or a proxy, execute router JavaScript, or write backups,
cookies, passwords, logs, or configuration XML to disk.

## Requirements

- Go `1.27.3`, managed by [Mise](https://mise.jdx.dev/).
- Local-network access to the router web interface and a valid account.
- An interactive terminal for hidden password entry.

Mise reads `mise.toml` automatically. To install the pinned runtime:

```sh
mise install
```

## Build and run

```sh
make build
./bin/digi-credentials
```

For safe operational diagnostics (with credentials, cookies, tokens, request
payloads, and backup contents omitted), run:

```sh
./bin/digi-credentials --debug
```

Close browser sessions to the router first. The program checks the served login
protocol, signs in once, finds the published backup endpoint, downloads and
decrypts the backup in memory, then prints Admin, PPPoE, and SIP credentials.
Missing, masked, or ambiguous fields are labelled instead of guessed.

## Security boundaries

- Connections are restricted to the entered numeric IP and normal HTTP(S)
  ports. Redirects and off-origin references are rejected.
- The login uses AES-CBC plus the router's RSA no-padding scheme. Backups are
  DES-ECB decrypted, MD5 checked, then bounded during LZSS decoding.
- It is intentionally specific to this firmware protocol and fails closed for
  unknown login or backup formats.
- As with any terminal application, RAM erasure, operating-system paging, and
  terminal recording cannot be controlled by the program.

## Development

```sh
make check
```

## Layout

- `cmd/digi-credentials`: executable entry point.
- `pkg/digicredentials`: router-reader implementation.
- `build`: build documentation and future build assets.
- `docs`: architecture documentation.

## License

GPL-3.0-or-later. The bounded LZSS decoder follows the algorithm documented by
[tpconf_bin_xml](https://github.com/sta-c0000/tpconf_bin_xml) by Alain
Ducharme. Key derivation follows
[tplink-firmware-tools](https://github.com/jqssun/tplink-firmware-tools).

## Fork and attribution

This repository is a Go rewrite of
[XGB430vProDigiDecrypt](https://github.com/vvalencian/XGB430vProDigiDecrypt)
by [vvalencian](https://github.com/vvalencian). It preserves the original
project's GPL-3.0-or-later licensing and protocol-specific security model while
reorganizing the implementation into Go packages. Changes in this fork are
identified in the Git history.

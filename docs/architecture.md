# Architecture

`cmd/digi-credentials` contains only process startup and exit handling.

`pkg/digicredentials` contains the reusable router reader: direct-IP transport,
login/session cryptography, backup derivation and decoding, configuration
parsing, credential selection, and safe debug logging. It does not persist
router data.

`build/` documents build-related repository assets. The root `Makefile` is
kept at the conventional location for `make` discovery.

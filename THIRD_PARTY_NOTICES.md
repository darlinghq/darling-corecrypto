# Third-party notices

The post-quantum backends and their test vectors are third-party material. The
attribution and licence notices that must be preserved with each file are kept
in the source files themselves; this file records where each component came
from so that the provenance is reviewable in one place.

## Post-quantum primitive implementations (`src/pqc/`)

- **Source:** [PQClean/PQClean](https://github.com/PQClean/PQClean), pinned at
  commit `0586a824fc0d49df0b6b6e9179d8d15d06d0974f`.
- **Components:** `ml-kem-768`, `ml-kem-1024`, `kyber768`, `kyber1024`,
  `ml-dsa-65`, `ml-dsa-87` (the portable C backends), plus `common/fips202*` and
  `common/compat.h`.
- **Licence:** CC0 / public-domain designation. The per-directory `LICENSE`
  files are retained verbatim, and file-level attribution comments in
  `common/fips202.c` (Ronny Van Keer; Gilles Van Assche, Daniel J. Bernstein and
  Peter Schwabe) are retained.
- **Modifications:** the backends were adapted to this library: symbol
  prefixes were adjusted, parameter sets were separated into their own include
  directories, RNG access was redirected through corecrypto's `ccrng`, and the
  ML-KEM key derivation was aligned with the `d || z` seed convention used by
  the corecrypto-compatible API. These are local adaptations, not upstream
  PQClean code as shipped.

## Curve25519 backend (`src/pqc/x25519/`)

- **Source:** OpenBSD's `curve25519.c` and `curve25519-generic.c` (revision
  headers `1.5` and `1.2`, 2019), derived from the public-domain ref10 Ed25519
  implementation in SUPERCOP 20141124.
- **Copyright:** Copyright (c) 2015, Google Inc.
- **Licence:** ISC. The full notices are retained at the top of both files.

## Test vectors (`tests/standalone/*_vectors.h`)

- **FIPS 203 / FIPS 204 vectors:** [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT).
  MIT License, Copyright (c) 2024 Krzysztof Kwiatkowski. The full notice is
  retained in every generated vector header.
- **Kyber vectors:** [GiacomoPope/kyber-py](https://github.com/GiacomoPope/kyber-py).
  MIT License, Copyright (c) 2025 Giacomo Pope. The full notice is retained in
  the generated vector headers.
- **X-Wing vectors:** Appendix C of
  [draft-connolly-cfrg-xwing-kem-07](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-07).
  The source and draft section are identified in `xwing_vectors.h`.

## Standards

The public API surface and algorithm behaviour are specified by NIST
FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and the public X-Wing draft. No Apple
corecrypto source was used.

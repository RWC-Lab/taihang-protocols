# Taihang Protocols

Taihang Protocols is a C++20 library of public-key, zero-knowledge, and
multi-party computation protocols built on the
[Taihang cryptographic core](https://github.com/RWC-Lab/taihang). It is the
protocol layer of the Taihang project family: Taihang supplies algebra,
symmetric primitives, networking, serialization, and foundational algorithms;
this repository composes those facilities into complete schemes and
interactive protocols.

Many modules originate from the earlier
[Kunlun](https://github.com/yuchen1024/Kunlun) research library. They are being
redesigned around Taihang's explicit contexts, separate public headers and
compiled implementations, consistent serialization, focused APIs, and
GoogleTest-based validation. This repository is not API-compatible with
Kunlun, and the migration does not imply that every Kunlun protocol has been
ported.

> [!WARNING]
> This is research and engineering software. The implementations have not been
> independently audited. Before deployment, review the security model,
> parameter selection, transcript construction, malicious/semi-honest
> assumptions, side channels, and network trust boundaries of each protocol.

## Project Position

```text
taihang-applications
        │
        ▼
taihang-protocols
        │
        ▼
      taihang
```

The dependency direction is intentionally one-way. Protocol code reuses the
core library; the core does not depend on any protocol or application.

## Implemented Modules

### Public-key encryption

| Module | Capability |
| --- | --- |
| ElGamal | Standard and exponential elliptic-curve ElGamal, homomorphic operations, rerandomization, and multi-recipient ciphertexts |
| Twisted ElGamal | Standard and exponential twisted ElGamal, homomorphic operations, rerandomization, and multi-recipient ciphertexts |

Bounded exponential decryption uses Taihang's configurable BSGS solver.

### Zero-knowledge proofs

| Family | Module |
| --- | --- |
| Sigma/Fiat-Shamir proofs | Discrete-log knowledge and discrete-log equality |
| Encryption statements | Twisted-ElGamal plaintext knowledge and multi-recipient plaintext equality |
| Range proofs | Inner-product argument and aggregated Bulletproof range proof |
| Composed range proofs | Twisted-ElGamal interval proofs from plaintext-knowledge or secret-key-knowledge witnesses |

Proof APIs use explicit `PublicParameters`, `Statement`, `Witness`, and `Proof`
types. Fiat-Shamir proofs use Taihang's default cryptographic hash and accept
optional associated context where binding to an outer protocol is required.

### Multi-party computation

| Area | Modules |
| --- | --- |
| Oblivious transfer | Naor-Pinkas base OT and ALSZ OT extension |
| OPRF | OT-extension-based OPRF and VOLE-based OPRF |
| VOLE | Vector oblivious linear evaluation over GF(2^128) |
| OKVS | Paxos and Baxos constructions |
| Private set operations | cwPRF mqRPMT, cwPRF PSI, unified mqRPMT intersection/union/cardinality/cardinality-sum, and Private-ID |

Protocol assumptions and supported modes are documented in the corresponding
public headers. Consult those interfaces before composing modules; similar
names do not imply identical adversarial models.

## Repository Layout

```text
taihang-protocols/
├── include/taihang/
│   ├── pke/                    # ElGamal encryption schemes
│   ├── zkp/
│   │   ├── sigma_protocols/    # Fiat-Shamir non-interactive proofs
│   │   └── range_proofs/       # Inner-product and range arguments
│   └── mpc/
│       ├── okvs/               # Paxos and Baxos
│       ├── oprf/               # OTE- and VOLE-based OPRFs
│       ├── ot/                 # Base OT and OT extension
│       ├── pso/                # Private set operations
│       └── vole/               # VOLE implementation
├── source/                     # Compiled implementations
├── tests/                      # GoogleTest functional and contract tests
├── benchmarks/                 # Standalone protocol benchmarks
├── experimental/               # Isolated optimization experiments
└── CMakeLists.txt
```

## Requirements

- CMake 3.21 or later
- A C++20 compiler
- OpenSSL
- OpenMP
- xxHash
- GoogleTest
- A sibling checkout of Taihang

The current build integrates the Taihang source tree directly and expects this
layout:

```text
parent-directory/
├── taihang/
└── taihang-protocols/
```

Taihang's own dependency requirements therefore also apply.

## Build and Test

From `taihang-protocols`:

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

When no build type is specified, the project defaults to `Debug`. This keeps
the `TAIHANG_ASSERT` contract checks used by death tests active. Use a separate
release tree for benchmarking:

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
```

Benchmark executables are generated from `benchmarks/bench_*.cpp`, including
programs for OT, Bulletproofs, ElGamal, cwPRF mqRPMT/PSI, Private-ID, and
mqRPMT-based private set operations. Run the desired executable directly from
the build directory, for example:

```bash
./build-release/bench_bullet_proof
./build-release/bench_cwprf_mqrpmt
./build-release/bench_mqrpmt_pso
```

Benchmarks report implementation throughput or latency, not protocol security.
Results are machine- and parameter-dependent and should be reproduced on the
target platform.

## Basic Usage

The following example performs standard elliptic-curve ElGamal encryption and
decryption:

```cpp
#include <openssl/obj_mac.h>

#include <taihang/pke/elgamal.hpp>

int main() {
    auto pp = taihang::pke::elgamal::setup(
        NID_X9_62_prime256v1);
    auto [public_key, secret_key] =
        taihang::pke::elgamal::keygen(pp);

    taihang::ECPoint message = pp.group_ctx->gen_random();
    taihang::pke::elgamal::Ciphertext ciphertext =
        taihang::pke::elgamal::encrypt(pp, public_key, message);

    taihang::ECPoint recovered =
        taihang::pke::elgamal::decrypt(secret_key, ciphertext);
    return recovered == message ? 0 : 1;
}
```

For a parent CMake project that keeps both repositories as siblings:

```cmake
add_subdirectory(path/to/taihang-protocols)
target_link_libraries(my_target PRIVATE taihang_protocols)
```

Do not add Taihang separately in the same build tree when using the current
top-level `taihang-protocols` CMake configuration; it already imports the
sibling core repository.

## Protocol and API Conventions

- Public setup material is represented explicitly, even when a protocol's
  standalone parameters are small. Composition-specific parameter derivation
  belongs to the composing module.
- Provers receive public parameters, a statement, and a witness. Verifiers
  receive only public inputs and the proof.
- Caller-owned algebraic values must use the contexts carried by the relevant
  public parameters. Context compatibility is part of the API contract.
- `TAIHANG_ASSERT` records caller and protocol contracts; it is disabled under
  `NDEBUG`. Required runtime work must not be placed inside an assertion.
- Stream deserialization of points, scalars, ciphertexts, and proofs requires
  context-dependent destination members to be initialized before reading.
- Network protocols expose separate sender/server and receiver/client roles.
  Both peers must use identical public parameters and framing expectations.
- Security parameters, set-size bounds, message ranges, and thread counts are
  protocol inputs. Do not infer them from untrusted peer data.

## Extending the Library

New modules should follow the existing repository structure: declarations and
explanatory protocol comments in `include/`, implementations in `source/`, and
focused tests in `tests/`. Public names should reflect the proved statement or
protocol role. Performance changes should be supported by a standalone,
reproducible benchmark without obscuring the mathematical structure of the
implementation.

## License

Taihang Protocols is released under the [MIT License](LICENSE).

# Experimental cwPRF mqRPMT optimizations

These files are intentionally outside the production build. They provide a
safe place to measure optimization ideas before changing
`source/mpc/pso/cwprf_mqrpmt.cpp`.

The benchmark compares:

- `baseline`: existing hash-to-`EC25519Point` path, followed by X25519.
- `current-parallel`: current Taihang wrapper path with the configured OpenMP
  parallel loop; this is the production-code reference row.
- `fused-direct`: hashes directly into a fixed 32-byte buffer and calls the
  public `x25519_scalar_mulx` primitive without temporary point allocation.
- `persistent-openmp`: the fused kernel inside a persistent OpenMP region.
- `chunked-pipeline`: a bounded producer/consumer pipeline that hashes chunks
  while the consumer performs X25519 multiplication. This models computation
  and transport overlap; it does not open a socket.

The benchmark also uses fixed-size point buffers and a local allocation-free
BloomFilter implementation. It computes both protocol layers (four total
X25519 batches) and checks the expected half-set intersection.

Build from the repository root without changing CMake:

```sh
c++ -O3 -std=gnu++20 -fPIC \
  -maes -msse4.1 -mpclmul -mavx -mavx2 -mrdseed \
  -Xclang -fopenmp -DXXH_EXPORT \
  -Iexperimental -Iinclude \
  -I/Users/yuchen/Documents/Coding/taihang/include \
  -I/Users/yuchen/Documents/Coding/taihang/third_party/robin_hood \
  experimental/cwprf_mqrpmt_optimized.cpp \
  experimental/bench_cwprf_mqrpmt_optimized.cpp \
  build/libtaihang_protocols.a build/taihang_core_build/libtaihang.a \
  /usr/local/lib/libcrypto.a /usr/local/lib/libxxhash.0.8.3.dylib \
  /usr/local/lib/libomp.dylib -Wl,-rpath,/usr/local/lib \
  -o /private/tmp/bench_cwprf_opt
```

Run with `set_log2_size` and `threads` arguments:

```sh
/private/tmp/bench_cwprf_opt 16 1
/private/tmp/bench_cwprf_opt 16 2
```

The production protocol and CMake target are not modified by these files.

# Curdleproofs

<center>
<img
    width="30%"
    src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/logo.jpg"
/>
</center>

[Curdleproofs](https://github.com/asn-d6/curdleproofs/blob/main/doc/curdleproofs.pdf) is a *zero-knowledge shuffle argument* inspired by [BG12](http://www0.cs.ucl.ac.uk/staff/J.Groth/MinimalShuffle.pdf).

Zero-knowledge shuffle arguments can have multiple use cases:
- [Secret leader election](https://ethresear.ch/t/whisk-a-practical-shuffle-based-ssle-protocol-for-ethereum/11763) protocols
- Message shuffling in [mixnets](https://eprint.iacr.org/2020/490.pdf)
- Universally verifiable [electronic voting](https://web.cs.ucdavis.edu/~franklin/ecs228/2013/neff_2001.pdf) protocols

## Documentation

The user-facing documentation for this library can be [found here](https://docs.rs/curdleproofs).

<center>
<img
    width="65%"
    src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/structure.png"
/>
</center>


In this library, we provide high-level protocol documentation for the core [`curdleproofs`] shuffle argument and its sub-arguments:

- [`same_scalar_argument`]
- [`same_permutation_argument`]
- [`grand_product_argument`]
- [`inner_product_argument`]
- [`same_multiscalar_argument`]

There are also notes on the [optimizations deployed](crate::notes::optimizations) to speed up the verifier.

For all the details and the security proofs, please see the [Curdleproofs paper](https://github.com/asn-d6/curdleproofs/blob/main/doc/curdleproofs.pdf).

## Performance

The following table gives the proof size as well as timings for proving and verifying Curdleproofs on an `Intel i7-8550U CPU @ 1.80GHz` over the BLS12-381 curve:

| Shuffled Elements | Proving (ms) | Verification (ms) | Shuffling (ms): | Proof Size (bytes) |
|------------------:|-------------:|------------------:|----------------:|-------------------:|
|                60 |          177 |                22 |              28 |               3968 |
|               124 |          304 |                27 |              57 |               4448 |
|               252 |          560 |                35 |             121 |               4928 |

_(The number of shuffled elements above is disturbingly close to a power of two but not quite, because we reserve four elements for zero-knowledge blinders.)_

## Example

The following example shows how to create and verify a shuffle proof that shuffles 28 elements:

```rust
# // The #-commented lines are hidden in Rustdoc but not in raw
# // markdown rendering, and contain boilerplate code so that the
# // code in the README.md is actually run as part of the test suite.
#
# use ark_std::rand::prelude::SliceRandom;
# use ark_std::UniformRand;
# use ark_bls12_381::Fr;
# use ark_bls12_381::G1Affine;
# use ark_bls12_381::G1Projective;
# use ark_ec::ProjectiveCurve;
# use ark_std::rand::{rngs::StdRng, SeedableRng};
# use core::iter;
#
# use curdleproofs::N_BLINDERS;
# use curdleproofs::curdleproofs::{CurdleproofsProof, generate_crs};
# use curdleproofs::util::shuffle_permute_and_commit_input;
#
# fn main() {
let mut rng = StdRng::seed_from_u64(0u64);

// Number of elements we are shuffling
let ell = 28;

// Construct the CRS
let crs = generate_crs(ell);

// Generate some witnesses: the permutation and the randomizer
let mut permutation: Vec<u32> = (0..ell as u32).collect();
permutation.shuffle(&mut rng);
let k = Fr::rand(&mut rng);

// Generate some shuffle input vectors
let vec_R: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
    .take(ell)
    .collect();
let vec_S: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
    .take(ell)
    .collect();

// Shuffle and permute inputs to generate output vectors and permutation commitments
let (vec_T, vec_U, M, vec_m_blinders) =
    shuffle_permute_and_commit_input(&crs, &vec_R, &vec_S, &permutation, &k, &mut rng);

// Generate a shuffle proof
let shuffle_proof = CurdleproofsProof::new(
    &crs,
    vec_R.clone(),
    vec_S.clone(),
    vec_T.clone(),
    vec_U.clone(),
    M,
    permutation,
    k,
    vec_m_blinders,
    &mut rng,
);

// Verify the shuffle proof
assert!(shuffle_proof
        .verify(&crs, &vec_R, &vec_S, &vec_T, &vec_U, &mut rng)
        .is_ok());
# }
```

## Building & Running

This library can be compiled with `cargo build` and requires rust nightly.

You can run the tests using `cargo test --release` and the benchmarks using `cargo bench`.

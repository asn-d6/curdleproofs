#![allow(non_snake_case)]
#![allow(unused_assignments)]

use ark_bls12_381::Fr;
use ark_bls12_381::G1Affine;
use ark_bls12_381::G1Projective;
use ark_ec::CurveGroup;
use ark_std::rand::prelude::SliceRandom;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::UniformRand;
use core::iter;
use core::time::Duration;
use criterion::*;
use std::ops::Mul;

use curdleproofs::curdleproofs::{generate_crs, CurdleproofsProof};
use curdleproofs::util::{generate_blinders, get_permutation, msm};

fn apply_permutation_group(vec_a: Vec<G1Affine>, permutation: &Vec<u32>) -> Vec<G1Affine> {
    permutation
        .into_iter()
        .map(|i| vec_a[*i as usize])
        .collect()
}

fn benchmark_shuffle(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);

    let N = 512;
    let N_BLINDERS = 4;
    let ell = N - N_BLINDERS;

    // Construct the CRS
    let crs = generate_crs(ell);

    // Get witnesses: the permutation, the randomizer, and a bunch of blinders
    let mut permutation: Vec<u32> = (0..ell as u32).collect();
    permutation.shuffle(&mut rng);
    let k = Fr::rand(&mut rng);
    let vec_r_m = generate_blinders(&mut rng, N_BLINDERS);

    // Get shuffle inputs
    let vec_R: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(ell)
        .collect();
    let vec_S: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(ell)
        .collect();

    // Derive shuffled outputs
    c.bench_function("shuffling", |b| {
        b.iter(|| {
            let mut vec_T: Vec<G1Affine> = vec_R.iter().map(|R| R.mul(k).into_affine()).collect();
            let mut vec_U: Vec<G1Affine> = vec_S.iter().map(|S| S.mul(k).into_affine()).collect();
            vec_T = apply_permutation_group(vec_T, &permutation);
            vec_U = apply_permutation_group(vec_U, &permutation);
        })
    });

    let mut vec_T: Vec<G1Affine> = vec_R.iter().map(|R| R.mul(k).into_affine()).collect();
    let mut vec_U: Vec<G1Affine> = vec_S.iter().map(|S| S.mul(k).into_affine()).collect();
    vec_T = apply_permutation_group(vec_T, &permutation);
    vec_U = apply_permutation_group(vec_U, &permutation);

    let range_as_fr: Vec<Fr> = (0..ell as u32).into_iter().map(|s| Fr::from(s)).collect();
    let sigma_ell = get_permutation(&range_as_fr, &permutation);
    let M = msm(&crs.vec_G, &sigma_ell) + msm(&crs.vec_H, &vec_r_m);

    c.bench_function("prover", |b| {
        b.iter(|| {
            CurdleproofsProof::new(
                &crs,
                vec_R.clone(),
                vec_S.clone(),
                vec_T.clone(),
                vec_U.clone(),
                M,
                permutation.clone(),
                k,
                vec_r_m.clone(),
                &mut rng,
            );
        })
    });

    let shuffle_proof = CurdleproofsProof::new(
        &crs,
        vec_R.clone(),
        vec_S.clone(),
        vec_T.clone(),
        vec_U.clone(),
        M,
        permutation,
        k,
        vec_r_m,
        &mut rng,
    );

    c.bench_function("verifier", |b| {
        b.iter(|| {
            assert!(shuffle_proof
                .verify(&crs, &vec_R, &vec_S, &vec_T, &vec_U, &M, &mut rng)
                .is_ok());
        })
    });
}

criterion_group! {name = shuffle;
                 config = Criterion::default().measurement_time(Duration::from_secs(60));
                 targets = benchmark_shuffle
}

criterion_main!(shuffle);

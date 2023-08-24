//! Utility functions used around Curdleproofs

#![allow(non_snake_case)]

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::RngCore;
use ark_std::{UniformRand, Zero};

use ark_ec::VariableBaseMSM;
use core::iter;
use std::ops::Mul;

use crate::crs::CurdleproofsCrs;
use crate::N_BLINDERS;

/// An ergonomic MSM function
///
pub fn msm(points: &[G1Affine], scalars: &[Fr]) -> G1Projective {
    assert_eq!(points.len(), scalars.len());
    G1Projective::msm(points, scalars).expect("number of points != number of scalars")
}

/// An ergonomic MSM function that works with projective points
pub fn msm_from_projective(points: &[G1Projective], scalars: &[Fr]) -> G1Projective {
    assert_eq!(points.len(), scalars.len());
    let points_affine = G1Projective::normalize_batch(points);
    msm(&points_affine, scalars)
}

/// Generate and return `n` blinders
pub fn generate_blinders<T: RngCore>(rng: &mut T, n: usize) -> Vec<Fr> {
    iter::repeat_with(|| Fr::rand(rng)).take(n).collect()
}

/// Get a bitstring to derive the verification scalars using binary decomposition. Used to [optimize the
/// verifier](crate::notes::optimizations#ipa-verification-scalars).
///
/// TODO: This can be done more elegantly
pub fn get_verification_scalars_bitstring(n: usize, logn: usize) -> Vec<Vec<usize>> {
    let mut bitstring: Vec<Vec<usize>> = Vec::new();
    for _i in 0..n {
        let vec_i: Vec<usize> = Vec::new();
        bitstring.push(vec_i);
    }

    for j in 0..logn {
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let current_bitstring = format!("{:b}", i);
            let mut bit_vec: Vec<char> = current_bitstring.chars().collect();
            bit_vec.reverse();
            while bit_vec.len() < logn {
                bit_vec.push('0');
            }

            if bit_vec[logn - j - 1] == '1' {
                bitstring[i].push(j);
            }
        }
    }

    bitstring
}

/// Return the inner product of two field vectors
pub fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
    assert!(a.len() == b.len());
    let mut c: Fr = Fr::zero();
    for i in 0..a.len() {
        c += a[i] * b[i];
    }
    c
}

/// Return `vec_a` permuted
pub fn get_permutation<T: Copy>(vec_a: &[T], permutation: &[u32]) -> Vec<T> {
    permutation.iter().map(|i| vec_a[*i as usize]).collect()
}

/// Given input vectors, the permutation and the randomizer, shuffle and permute the input.  Basically, prepare
/// everything so that a shuffle proof can be created!
pub fn shuffle_permute_and_commit_input<T: RngCore>(
    crs: &CurdleproofsCrs,
    vec_R: &[G1Affine],
    vec_S: &[G1Affine],
    permutation: &[u32],
    k: &Fr,
    rng: &mut T,
) -> (Vec<G1Affine>, Vec<G1Affine>, G1Projective, Vec<Fr>) {
    let ell = crs.vec_G.len();

    // Derive shuffled outputs
    let mut vec_T: Vec<G1Affine> = vec_R.iter().map(|R| R.mul(k).into_affine()).collect();
    let mut vec_U: Vec<G1Affine> = vec_S.iter().map(|S| S.mul(k).into_affine()).collect();
    vec_T = get_permutation(&vec_T, permutation);
    vec_U = get_permutation(&vec_U, permutation);

    let range_as_fr: Vec<Fr> = (0..ell as u32).map(Fr::from).collect();
    let sigma_ell = get_permutation(&range_as_fr, permutation);

    let vec_m_blinders = generate_blinders(rng, N_BLINDERS);
    let M = msm(&crs.vec_G, &sigma_ell) + msm(&crs.vec_H, &vec_m_blinders);

    (vec_T, vec_U, M, vec_m_blinders)
}

pub(crate) fn sum_affine_points(affine_points: &[G1Affine]) -> G1Affine {
    affine_points
        .iter()
        .map(|affine| affine.into_group())
        .sum::<G1Projective>()
        .into_affine()
}

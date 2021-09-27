#![allow(non_snake_case)]
use core::iter;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One};
use ark_std::rand::RngCore;
use ark_std::Zero;

use crate::transcript::CurdleproofsTranscript;
use merlin::Transcript;

use crate::errors::ProofError;
use crate::inner_product_argument::InnerProductProof;
use crate::msm_accumulator::MsmAccumulator;
use crate::util::{generate_blinders, inner_product, msm};

/// A GrandProduct proof object
#[derive(Clone, Debug)]
pub struct GrandProductProof {
    C: G1Projective,

    r_p: Fr,

    ipa_proof: InnerProductProof,
}

impl GrandProductProof {
    /// Create a GrandProduct proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{g}$ CRS vector
    /// * `crs_H_vec` - $\bm{h}$ CRS blinder vector
    /// * `crs_U` - $H$ CRS element
    /// * `B` - commitment to `vec_b`
    /// * `gprod_result` - grand product result
    /// * `vec_b` - vector of grand product factors (*witness*)
    /// * `vec_b_blinders` - blinders for `B` (*witness*)
    pub fn new<T: RngCore>(
        crs_G_vec: &Vec<G1Affine>,
        crs_H_vec: &Vec<G1Affine>,
        crs_U: &G1Projective, // This is actually H in the paper

        B: G1Projective,
        gprod_result: Fr,

        vec_b: Vec<Fr>,
        vec_b_blinders: Vec<Fr>, // vec_r_b in the paper

        transcript: &mut Transcript,
        rng: &mut T,
    ) -> GrandProductProof {
        let n_blinders = vec_b_blinders.len();
        let ell = crs_G_vec.len();
        let n = ell + n_blinders;
        let ell_plus_one = (ell + 1) as u64; // we use this below as an argument to pow()

        // Step 1
        transcript.append(b"gprod_step1", &B);
        transcript.append(b"gprod_step1", &gprod_result);
        let alpha = transcript.get_and_append_challenge(b"gprod_alpha");

        // Step 2
        // Setup vec_c = {1, b_1, b_1*b_2, b_1*b_2*b_3, ... }
        let mut vec_c: Vec<Fr> = Vec::with_capacity(ell);
        vec_c.push(Fr::one());
        for (i, b_i) in vec_b[..ell - 1].iter().enumerate() {
            vec_c.push(vec_c[i] * b_i);
        }

        let vec_c_blinders = generate_blinders(rng, n_blinders); // vec_r_c in the paper
        let C = msm(crs_G_vec, &vec_c) + msm(crs_H_vec, &vec_c_blinders);

        // Compute r_p
        let vec_r_b_plus_alpha: Vec<Fr> =
            vec_b_blinders.iter().map(|r_b_i| *r_b_i + alpha).collect();
        let r_p = inner_product(&vec_r_b_plus_alpha, &vec_c_blinders);

        transcript.append(b"gprod_step2", &C);
        transcript.append(b"gprod_step2", &r_p);
        let beta = transcript.get_and_append_challenge(b"gprod_beta");
        let beta_inv = beta.inverse().expect("beta must have an inverse");

        // Step 3
        // Build the new G' basis
        let mut vec_G_prime: Vec<G1Affine> = Vec::with_capacity(ell);
        let mut pow_beta_inv = beta_inv;
        for G_i in crs_G_vec.iter() {
            let G_prime = G_i.mul(pow_beta_inv).into_affine();
            vec_G_prime.push(G_prime);
            pow_beta_inv *= beta_inv;
        }

        // Build the new H' basis
        let vec_H_prime: Vec<G1Affine> = crs_H_vec
            .iter()
            .map(|H_i| H_i.mul(beta_inv.pow([ell_plus_one])).into_affine())
            .collect();

        // Build the new b' and d vectors
        let mut vec_b_prime: Vec<Fr> = Vec::with_capacity(ell);
        let mut pow_beta = beta;
        for b_i in vec_b.into_iter() {
            vec_b_prime.push(b_i * pow_beta);
            pow_beta *= beta;
        }

        // Build d
        let mut vec_d: Vec<Fr> = Vec::with_capacity(n);
        let mut pow_beta = Fr::one();
        let mut vec_beta_powers: Vec<Fr> = Vec::with_capacity(ell);
        for b_prime_i in vec_b_prime {
            vec_d.push(b_prime_i - pow_beta);
            vec_beta_powers.push(pow_beta);
            pow_beta *= beta;
        }

        // Build vector r_d
        let vec_d_blinders: Vec<Fr> = vec_r_b_plus_alpha
            .iter()
            .map(|f_i| beta.pow([ell_plus_one]) * f_i)
            .collect();

        // Create D commitment
        let vec_alphabeta: Vec<Fr> = iter::repeat(alpha * (beta.pow([ell_plus_one])))
            .take(n_blinders)
            .collect();
        let D = B - msm(&vec_G_prime, &vec_beta_powers) + msm(&vec_H_prime, &vec_alphabeta);

        // Step 4
        // Build G
        let mut vec_G = crs_G_vec.clone();
        vec_G.extend(crs_H_vec);
        // Build G'
        vec_G_prime.extend(vec_H_prime);

        let inner_prod =
            r_p * beta.pow([(ell + 1) as u64]) + gprod_result * beta.pow([ell as u64]) - Fr::one();

        vec_c.extend(vec_c_blinders);
        vec_d.extend(vec_d_blinders);

        // Sanity checks
        debug_assert!(inner_product(&vec_c, &vec_d) == inner_prod); // check inner product
        debug_assert!((msm(&vec_G, &vec_c) - C).is_zero()); // check C commitment
        debug_assert!((msm(&vec_G_prime, &vec_d) - D).is_zero()); // check D commitment

        let ipa_proof = InnerProductProof::new(
            vec_G,
            vec_G_prime,
            crs_U,
            C,
            D,
            inner_prod,
            vec_c,
            vec_d,
            transcript,
            rng,
        );

        GrandProductProof { C, r_p, ipa_proof }
    }

    /// Verify a GrandProduct proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{g}$ CRS vector
    /// * `crs_H_vec` - $\bm{h}$ CRS blinder vector
    /// * `crs_U` - $H$ CRS element
    /// * `crs_G_sum` - CRS sum of `crs_G_vec` (grand product argument [optimization](crate::notes::optimizations#grandproduct-verifier-optimizations))
    /// * `crs_H_sum` - CRS sum of `crs_H_vec` (grand product argument [optimization](crate::notes::optimizations#grandproduct-verifier-optimizations))
    /// * `B` - commitment to `vec_b`
    /// * `gprod_result` - grand product result
    pub fn verify<T: RngCore>(
        &self,

        crs_G_vec: &Vec<G1Affine>,
        crs_H_vec: &Vec<G1Affine>,
        crs_U: &G1Projective, // This is actually H in the paper
        crs_G_sum: &G1Affine,
        crs_H_sum: &G1Affine,

        B: G1Projective,
        gprod_result: Fr,

        n_blinders: usize,
        transcript: &mut Transcript,
        msm_accumulator: &mut MsmAccumulator,

        rng: &mut T,
    ) -> Result<(), ProofError> {
        let ell = crs_G_vec.len();
        let ell_plus_one = (ell + 1) as u64; // we use this below as an argument to pow()

        // Step 1
        transcript.append(b"gprod_step1", &B);
        transcript.append(b"gprod_step1", &gprod_result);
        let alpha = transcript.get_and_append_challenge(b"gprod_alpha");

        // Step 2
        transcript.append(b"gprod_step2", &self.C);
        transcript.append(b"gprod_step2", &self.r_p);
        let beta = transcript.get_and_append_challenge(b"gprod_beta");
        let beta_inv = beta.inverse().expect("beta must have an inverse");

        // Step 3
        // Build `vec_u` for the optimization trick
        let mut vec_u: Vec<Fr> = Vec::with_capacity(ell);
        let mut pow_beta_inv = beta_inv;
        for _ in 0..ell {
            vec_u.push(pow_beta_inv);
            pow_beta_inv *= beta_inv;
        }
        vec_u.extend(iter::repeat(beta_inv.pow([ell_plus_one])).take(n_blinders));

        // Compute D
        let D = B - crs_G_sum.mul(beta_inv) + crs_H_sum.mul(alpha);

        // Step 4
        // Build G
        let mut vec_G = crs_G_vec.clone();
        vec_G.extend(crs_H_vec);

        let inner_prod =
            self.r_p * beta.pow([ell_plus_one]) + gprod_result * beta.pow([ell as u64]) - Fr::one();

        self.ipa_proof.verify(
            &vec_G,
            crs_U,
            self.C,
            D,
            inner_prod,
            vec_u,
            transcript,
            msm_accumulator,
            rng,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
    use ark_std::UniformRand;
    use core::iter;

    #[test]
    fn test_gprod_argument() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut transcript_prover = merlin::Transcript::new(b"gprod");

        let n = 128;
        let n_blinders = 4;
        let ell = n - n_blinders;

        let crs_G_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(ell)
            .collect();
        let crs_H_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(n_blinders)
            .collect();
        let crs_U = G1Projective::rand(&mut rng);
        let crs_G_sum: G1Affine = crs_G_vec.iter().sum();
        let crs_H_sum: G1Affine = crs_H_vec.iter().sum();

        let vec_b: Vec<Fr> = iter::repeat_with(|| rng.gen()).take(ell).collect();
        let vec_b_blinders = generate_blinders(&mut rng, n_blinders);

        // Compute gprod result without the blinders
        let gprod_result = vec_b.iter().product();

        let B = msm(&crs_G_vec, &vec_b) + msm(&crs_H_vec, &vec_b_blinders);

        let gprod_proof = GrandProductProof::new(
            &crs_G_vec,
            &crs_H_vec,
            &crs_U,
            B,
            gprod_result,
            vec_b.clone(),
            vec_b_blinders.clone(),
            &mut transcript_prover,
            &mut rng,
        );

        // Reset the FS
        let mut transcript_verifier = merlin::Transcript::new(b"gprod");
        let mut msm_accumulator = MsmAccumulator::new();

        assert!(gprod_proof
            .verify(
                &crs_G_vec,
                &crs_H_vec,
                &crs_U,
                &crs_G_sum,
                &crs_H_sum,
                B,
                gprod_result,
                n_blinders,
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());

        assert!(msm_accumulator.verify().is_ok());

        ////////////////////////////////////////////////////
        // Basic testing for false proof with wrong gprod result
        let mut transcript_verifier = merlin::Transcript::new(b"gprod");
        let mut msm_accumulator = MsmAccumulator::new();
        assert!(gprod_proof
            .verify(
                &crs_G_vec,
                &crs_H_vec,
                &crs_U,
                &crs_G_sum,
                &crs_H_sum,
                B,
                gprod_result + Fr::one(),
                n_blinders,
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());
        assert!(msm_accumulator.verify().is_err());

        //  Wrong commitment to vec_b
        let mut transcript_verifier = merlin::Transcript::new(b"gprod");
        let mut msm_accumulator = MsmAccumulator::new();
        assert!(gprod_proof
            .verify(
                &crs_G_vec,
                &crs_H_vec,
                &crs_U,
                &crs_G_sum,
                &crs_H_sum,
                B.mul(Fr::rand(&mut rng).into_repr()),
                gprod_result,
                n_blinders,
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());
        assert!(msm_accumulator.verify().is_err());
    }
}

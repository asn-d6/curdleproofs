#![allow(non_snake_case)]
use core::iter;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::group::Group;
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::RngCore;

use crate::transcript::CurdleproofsTranscript;
use merlin::Transcript;

use crate::errors::ProofError;
use crate::grand_product_argument::GrandProductProof;
use crate::msm_accumulator::MsmAccumulator;
use crate::util::{get_permutation, msm};

/// A same permutation proof object
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SamePermutationProof {
    B: G1Projective,

    grand_product_proof: GrandProductProof,
}

impl SamePermutationProof {
    /// Create a same permutation proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{g}$ CRS vector
    /// * `crs_H_vec` - $\bm{h}$ CRS vector
    /// * `crs_U` - $\bm{H}$ CRS element
    /// * `A` - commitment to permuted `vec_a`
    /// * `M` - commitment to `permutation`
    /// * `vec_a` - scalar vector
    /// * `permutation` - shuffle permutation (*witness*)
    /// * `vec_a_blinders` - blinders for `vec_a` (*witness*)
    /// * `vec_m_blinders` - blinders for `vec_m` (*witness*)
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: RngCore>(
        crs_G_vec: &Vec<G1Affine>,
        crs_H_vec: &Vec<G1Affine>,
        crs_U: &G1Projective, // This is actually H in the paper

        A: G1Projective,
        M: G1Projective,
        vec_a: &Vec<Fr>,

        permutation: Vec<u32>,
        vec_a_blinders: Vec<Fr>, // vec_r_a in the paper
        vec_m_blinders: Vec<Fr>, // vec_r_m in the paper

        transcript: &mut Transcript,
        rng: &mut T,
    ) -> SamePermutationProof {
        let n_blinders = vec_a_blinders.len();
        let ell = crs_G_vec.len();

        // Step 1
        transcript.append_list(b"same_perm_step1", &[&A, &M]);
        transcript.append_list(b"same_perm_step1", &[vec_a]);
        let alpha = transcript.get_and_append_challenge(b"same_perm_alpha");
        let beta = transcript.get_and_append_challenge(b"same_perm_beta");

        // Step 2
        let vec_a_permuted = get_permutation(vec_a, &permutation);
        let permutation_as_fr = permutation.iter().map(|s| Fr::from(*s));
        let permuted_polynomial_factors: Vec<Fr> = vec_a_permuted
            .iter()
            .zip(permutation_as_fr)
            .map(|(a, m)| *a + m * alpha + beta)
            .collect();
        let gprod_result: Fr = permuted_polynomial_factors.iter().product();

        let vec_beta_repeated: Vec<Fr> = iter::repeat(beta).take(ell).collect();
        let B = A + M.mul(alpha.into_repr()) + msm(crs_G_vec, &vec_beta_repeated);

        let mut vec_b_blinders = Vec::with_capacity(n_blinders);
        for i in 0..n_blinders {
            vec_b_blinders.push(vec_a_blinders[i] + alpha * vec_m_blinders[i]);
        }

        let grand_product_proof = GrandProductProof::new(
            crs_G_vec,
            crs_H_vec,
            crs_U,
            B,
            gprod_result,
            permuted_polynomial_factors,
            vec_b_blinders,
            transcript,
            rng,
        );

        SamePermutationProof {
            B,
            grand_product_proof,
        }
    }

    /// Verify a same permutation proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{g}$ CRS vector
    /// * `crs_H_vec` - $\bm{h}$ CRS vector
    /// * `crs_U` - $\bm{H}$ CRS element
    /// * `A` - commitment to permuted `vec_a`
    /// * `M` - commitment to `permutation`
    /// * `vec_a` - scalar vector
    #[allow(clippy::too_many_arguments)]
    pub fn verify<T: RngCore>(
        &self,

        crs_G_vec: &Vec<G1Affine>,
        crs_H_vec: &Vec<G1Affine>,
        crs_U: &G1Projective, // This is actually H in the paper
        crs_G_sum: &G1Affine,
        crs_H_sum: &G1Affine,

        A: &G1Projective,
        M: &G1Projective,
        vec_a: &Vec<Fr>,

        n_blinders: usize,
        transcript: &mut Transcript,
        msm_accumulator: &mut MsmAccumulator,

        rng: &mut T,
    ) -> Result<(), ProofError> {
        let ell = crs_G_vec.len();

        // Step 1
        transcript.append_list(b"same_perm_step1", &[A, M]);
        transcript.append_list(b"same_perm_step1", &[vec_a]);
        let alpha = transcript.get_and_append_challenge(b"same_perm_alpha");
        let beta = transcript.get_and_append_challenge(b"same_perm_beta");

        // Step 2
        let range_as_fr = (0..ell as u32).map(Fr::from);
        let polynomial_factors = vec_a
            .iter()
            .zip(range_as_fr)
            .map(|(a, i)| *a + i * alpha + beta);
        let gprod_result: Fr = polynomial_factors.product();

        let vec_beta_repeated: Vec<Fr> = iter::repeat(beta).take(ell).collect();

        msm_accumulator.accumulate_check(
            &(self.B - A - M.mul(&alpha)),
            &vec_beta_repeated,
            crs_G_vec,
            rng,
        );

        self.grand_product_proof.verify(
            crs_G_vec,
            crs_H_vec,
            crs_U,
            crs_G_sum,
            crs_H_sum,
            self.B,
            gprod_result,
            n_blinders,
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
    use ark_ec::ProjectiveCurve;
    use ark_std::rand::prelude::SliceRandom;
    use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
    use ark_std::UniformRand;
    use core::iter;

    use crate::util::generate_blinders;

    #[test]
    fn test_same_perm_argument() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut transcript_prover = merlin::Transcript::new(b"sameperm");

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

        let vec_a_blinders = generate_blinders(&mut rng, n_blinders);
        let vec_m_blinders = generate_blinders(&mut rng, n_blinders);

        let mut permutation: Vec<u32> = (0..ell as u32).collect();
        permutation.shuffle(&mut rng);
        let permutation_as_fr: Vec<Fr> = permutation.iter().map(|s| Fr::from(*s)).collect();

        let vec_a: Vec<Fr> = iter::repeat_with(|| rng.gen()).take(ell).collect();
        let vec_a_permuted = get_permutation(&vec_a, &permutation);

        let A = msm(&crs_G_vec, &vec_a_permuted) + msm(&crs_H_vec, &vec_a_blinders);
        let M = msm(&crs_G_vec, &permutation_as_fr) + msm(&crs_H_vec, &vec_m_blinders);

        let same_perm_proof = SamePermutationProof::new(
            &crs_G_vec,
            &crs_H_vec,
            &crs_U,
            A,
            M,
            &vec_a,
            permutation,
            vec_a_blinders,
            vec_m_blinders,
            &mut transcript_prover,
            &mut rng,
        );

        // Reset the FS
        let mut transcript_verifier = merlin::Transcript::new(b"sameperm");
        let mut msm_accumulator = MsmAccumulator::new();

        assert!(same_perm_proof
            .verify(
                &crs_G_vec,
                &crs_H_vec,
                &crs_U,
                &crs_G_sum,
                &crs_H_sum,
                &A,
                &M,
                &vec_a,
                n_blinders,
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());

        assert!(msm_accumulator.verify().is_ok());

        ////////////////////////////////////////////////////
        // Reset the FS
        let mut transcript_verifier = merlin::Transcript::new(b"sameperm");
        let mut msm_accumulator = MsmAccumulator::new();

        assert!(same_perm_proof
            .verify(
                &crs_G_vec,
                &crs_H_vec,
                &crs_U,
                &crs_G_sum,
                &crs_H_sum,
                &A,
                &M,
                &vec_a,
                n_blinders,
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());

        assert!(msm_accumulator.verify().is_ok())
    }
}

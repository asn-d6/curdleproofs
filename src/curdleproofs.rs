#![allow(non_snake_case)]
pub use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::RngCore;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::{UniformRand, Zero};

use crate::errors::ProofError;
use crate::util::{generate_blinders, get_permutation, msm, sum_affine_points};
use core::iter;
use std::ops::Mul;

use crate::transcript::CurdleproofsTranscript;

use crate::commitments::GroupCommitment;
use crate::msm_accumulator::MsmAccumulator;
use crate::same_multiscalar_argument::SameMultiscalarProof;
use crate::same_permutation_argument::SamePermutationProof;
use crate::same_scalar_argument::SameScalarProof;

use crate::N_BLINDERS;

/// The Curdleproofs CRS
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CurdleproofsCrs {
    /// Pedersen commitment bases
    pub vec_G: Vec<G1Affine>,
    /// Pedersen commitment blinder bases
    pub vec_H: Vec<G1Affine>,
    /// Base used in the *SameScalar* argument
    pub H: G1Projective,
    /// Base used in the *SameScalar* argument
    pub G_t: G1Projective,
    /// Base used in the *SameScalar* argument
    pub G_u: G1Projective,
    /// Sum of vec_G (grand product argument [optimization](crate::notes::optimizations#grandproduct-verifier-optimizations))
    pub G_sum: G1Affine,
    /// Sum of vec_H (grand product argument [optimization](crate::notes::optimizations#grandproduct-verifier-optimizations))
    pub H_sum: G1Affine,
}

/// Generate a randomly generated CRS
pub fn generate_crs(ell: usize) -> CurdleproofsCrs {
    let mut rng = StdRng::seed_from_u64(0u64);

    let crs_G_vec: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(ell)
        .collect();
    let crs_H_vec: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(N_BLINDERS)
        .collect();
    let crs_H = G1Projective::rand(&mut rng);
    let crs_G_t = G1Projective::rand(&mut rng);
    let crs_G_u = G1Projective::rand(&mut rng);
    let crs_G_sum: G1Affine = sum_affine_points(&crs_G_vec);
    let crs_H_sum: G1Affine = sum_affine_points(&crs_H_vec);

    CurdleproofsCrs {
        vec_G: crs_G_vec,
        vec_H: crs_H_vec,
        H: crs_H,
        G_t: crs_G_t,
        G_u: crs_G_u,
        G_sum: crs_G_sum,
        H_sum: crs_H_sum,
    }
}

/// A Curdleproofs proof object
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CurdleproofsProof {
    A: G1Projective,
    cm_T: GroupCommitment,
    cm_U: GroupCommitment,

    R: G1Projective,
    S: G1Projective,

    same_perm_proof: SamePermutationProof,
    same_scalar_proof: SameScalarProof,
    same_multiscalar_proof: SameMultiscalarProof,
}

impl CurdleproofsProof {
    /// Create a shuffle proof
    ///
    /// # Arguments
    ///
    /// * `crs` - The Curdleproofs CRS
    /// * `vec_R` - Input vector **R**
    /// * `vec_S` - Input vector **S**
    /// * `vec_T` - Output vector **T**
    /// * `vec_U` - Output vector **U**
    /// * `M` - Commitment to `permutation`
    /// * `permutation` - Permutation (*witness*)
    /// * `k` - Randomizer (*witness*)
    /// * `vec_m_blinders` - $\\bm{r_m}$ blinders for the permutation commitment (*witness*)
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: RngCore>(
        crs: &CurdleproofsCrs,

        vec_R: Vec<G1Affine>,
        vec_S: Vec<G1Affine>,
        vec_T: Vec<G1Affine>,
        vec_U: Vec<G1Affine>,
        M: G1Projective,

        permutation: Vec<u32>,
        k: Fr,
        vec_m_blinders: Vec<Fr>,

        rng: &mut T,
    ) -> CurdleproofsProof {
        // Number of non-blinder elements used in this proof
        let ell = vec_R.len();

        // Our Fiat-Shamir transcript
        let mut transcript = merlin::Transcript::new(b"curdleproofs");

        // Step 1
        transcript.append_list(b"curdleproofs_step1", &[&vec_R, &vec_S, &vec_T, &vec_U]);
        transcript.append(b"curdleproofs_step1", &M);
        let vec_a = transcript.get_and_append_challenges(b"curdleproofs_vec_a", ell);

        // Step 2
        let vec_a_blinders = generate_blinders(rng, N_BLINDERS - 2);

        let mut vec_r_a_prime = vec_a_blinders.clone();
        vec_r_a_prime.extend([Fr::zero(), Fr::zero()]);

        let vec_a_permuted = get_permutation(&vec_a, &permutation);

        let A = msm(&crs.vec_G, &vec_a_permuted) + msm(&crs.vec_H, &vec_r_a_prime);

        let same_perm_proof = SamePermutationProof::new(
            &crs.vec_G,
            &crs.vec_H,
            &crs.H,
            A,
            M,
            &vec_a,
            permutation,
            vec_r_a_prime,
            vec_m_blinders,
            &mut transcript,
            rng,
        );

        // Step 3
        let r_t = Fr::rand(rng);
        let r_u = Fr::rand(rng);
        let R = msm(&vec_R, &vec_a);
        let S = msm(&vec_S, &vec_a);

        let cm_T = GroupCommitment::new(&crs.G_t, &crs.H, R.mul(k), r_t);
        let cm_U = GroupCommitment::new(&crs.G_u, &crs.H, S.mul(k), r_u);

        let same_scalar_proof = SameScalarProof::new(
            &crs.G_t,
            &crs.G_u,
            &crs.H,
            R,
            S,
            cm_T,
            cm_U,
            k,
            r_t,
            r_u,
            &mut transcript,
            rng,
        );

        // Step 4
        let A_prime = A + cm_T.T_1 + cm_U.T_1;

        let mut vec_G_with_blinders = crs.vec_G.clone();
        vec_G_with_blinders.extend(&crs.vec_H[..N_BLINDERS - 2]);
        vec_G_with_blinders.push(crs.G_t.into_affine());
        vec_G_with_blinders.push(crs.G_u.into_affine());

        let mut vec_T_with_blinders = vec_T;
        vec_T_with_blinders.extend([
            G1Affine::zero(),
            G1Affine::zero(),
            crs.H.into_affine(),
            G1Affine::zero(),
        ]);

        let mut vec_U_with_blinders = vec_U;
        vec_U_with_blinders.extend([
            G1Affine::zero(),
            G1Affine::zero(),
            G1Affine::zero(),
            crs.H.into_affine(),
        ]);

        let mut vec_a_with_blinders = vec_a_permuted;
        vec_a_with_blinders.extend(vec_a_blinders);
        vec_a_with_blinders.push(r_t);
        vec_a_with_blinders.push(r_u);

        let same_multiscalar_proof = SameMultiscalarProof::new(
            vec_G_with_blinders,
            A_prime,
            cm_T.T_2,
            cm_U.T_2,
            vec_T_with_blinders,
            vec_U_with_blinders,
            vec_a_with_blinders,
            &mut transcript,
            rng,
        );

        CurdleproofsProof {
            A,
            cm_T,
            cm_U,
            R,
            S,
            same_perm_proof,
            same_scalar_proof,
            same_multiscalar_proof,
        }
    }

    /// Verify a shuffle proof
    ///
    /// # Arguments
    ///
    /// * `crs` - The Curdleproofs CRS
    /// * `vec_R` - Input vector **R**
    /// * `vec_S` - Input vector **S**
    /// * `vec_T` - Output vector **T**
    /// * `vec_U` - Output vector **U**
    /// * `M` - Commitment to `permutation`
    #[allow(clippy::too_many_arguments)]
    pub fn verify<T: RngCore>(
        &self,
        crs: &CurdleproofsCrs,

        vec_R: &Vec<G1Affine>,
        vec_S: &Vec<G1Affine>,
        vec_T: &Vec<G1Affine>,
        vec_U: &Vec<G1Affine>,
        M: &G1Projective,

        rng: &mut T,
    ) -> Result<(), ProofError> {
        // Number of non-blinder elements used in this proof
        let ell = vec_R.len();

        // Our Fiat-Shamir transcript
        let mut transcript = merlin::Transcript::new(b"curdleproofs");
        // Our MSM accumulator
        let mut msm_accumulator = MsmAccumulator::new();

        // Make sure that randomizer was not the zero element (and wiped out the ciphertexts)
        if vec_T[0].is_zero() {
            return Err(ProofError::VerificationError);
        }

        // Step 1
        transcript.append_list(b"curdleproofs_step1", &[vec_R, vec_S, vec_T, vec_U]);
        transcript.append(b"curdleproofs_step1", M);
        let vec_a = transcript.get_and_append_challenges(b"curdleproofs_vec_a", ell);

        // Step 2
        // Verify the grand product proof
        self.same_perm_proof.verify(
            &crs.vec_G,
            &crs.vec_H,
            &crs.H,
            &crs.G_sum,
            &crs.H_sum,
            &self.A,
            M,
            &vec_a,
            N_BLINDERS,
            &mut transcript,
            &mut msm_accumulator,
            rng,
        )?;

        // Step 3
        self.same_scalar_proof.verify(
            &crs.G_t,
            &crs.G_u,
            &crs.H,
            self.R,
            self.S,
            self.cm_T,
            self.cm_U,
            &mut transcript,
        )?;

        // Step 4
        let A_prime = self.A + self.cm_T.T_1 + self.cm_U.T_1;

        let mut vec_G_with_blinders = crs.vec_G.clone();
        vec_G_with_blinders.extend(&crs.vec_H[..N_BLINDERS - 2]);
        vec_G_with_blinders.push(crs.G_t.into_affine());
        vec_G_with_blinders.push(crs.G_u.into_affine());

        let mut vec_T_with_blinders = vec_T.clone();
        vec_T_with_blinders.extend([
            G1Affine::zero(),
            G1Affine::zero(),
            crs.H.into_affine(),
            G1Affine::zero(),
        ]);

        let mut vec_U_with_blinders = vec_U.clone();
        vec_U_with_blinders.extend([
            G1Affine::zero(),
            G1Affine::zero(),
            G1Affine::zero(),
            crs.H.into_affine(),
        ]);

        self.same_multiscalar_proof.verify(
            &vec_G_with_blinders,
            A_prime,
            self.cm_T.T_2,
            self.cm_U.T_2,
            &vec_T_with_blinders,
            &vec_U_with_blinders,
            &mut transcript,
            &mut msm_accumulator,
            rng,
        )?;

        // Finally check the correctness of R and S
        msm_accumulator.accumulate_check(&self.R, &vec_a, vec_R, rng);
        msm_accumulator.accumulate_check(&self.S, &vec_a, vec_S, rng);

        // Do the final verification on our MSM accumulator
        msm_accumulator.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::shuffle_permute_and_commit_input;
    use ark_std::rand::prelude::SliceRandom;
    use ark_std::UniformRand;

    #[test]
    fn test_shuffle_argument() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let N = 64;
        let ell = N - N_BLINDERS;

        // Construct the CRS
        let crs: CurdleproofsCrs = generate_crs(ell);

        // Get witnesses: the permutation, the randomizer, and a bunch of blinders
        let mut permutation: Vec<u32> = (0..ell as u32).collect();
        permutation.shuffle(&mut rng);
        let k = Fr::rand(&mut rng);

        // Get shuffle inputs
        let vec_R: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(ell)
            .collect();
        let vec_S: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(ell)
            .collect();

        let (vec_T, vec_U, M, vec_m_blinders) =
            shuffle_permute_and_commit_input(&crs, &vec_R, &vec_S, &permutation, &k, &mut rng);

        let shuffle_proof = CurdleproofsProof::new(
            &crs,
            vec_R.clone(),
            vec_S.clone(),
            vec_T.clone(),
            vec_U.clone(),
            M,
            permutation.clone(),
            k,
            vec_m_blinders.clone(),
            &mut rng,
        );

        // Test a correct shuffle proof
        assert!(shuffle_proof
            .verify(&crs, &vec_R, &vec_S, &vec_T, &vec_U, &M, &mut rng)
            .is_ok());
    }

    // Some basic dumb tests for bad proofs
    //
    // TODO: To do actual soundness tests we would need to dig into the proof generation code and mutate elements to
    // attempt to surgically manipulate the security proofs.
    #[test]
    fn test_bad_shuffle_arguments() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let N = 128;
        let ell = N - N_BLINDERS;

        // Construct the CRS
        let crs: CurdleproofsCrs = generate_crs(ell);

        // Get witnesses: the permutation, the randomizer, and a bunch of blinders
        let mut permutation: Vec<u32> = (0..ell as u32).collect();
        permutation.shuffle(&mut rng);
        let k = Fr::rand(&mut rng);

        // Get shuffle inputs
        let vec_R: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(ell)
            .collect();
        let vec_S: Vec<G1Affine> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(ell)
            .collect();

        let (vec_T, vec_U, M, vec_m_blinders) =
            shuffle_permute_and_commit_input(&crs, &vec_R, &vec_S, &permutation, &k, &mut rng);

        let shuffle_proof = CurdleproofsProof::new(
            &crs,
            vec_R.clone(),
            vec_S.clone(),
            vec_T.clone(),
            vec_U.clone(),
            M,
            permutation.clone(),
            k,
            vec_m_blinders.clone(),
            &mut rng,
        );

        // Let's get another permutation for these bad proofs
        let mut another_permutation: Vec<u32> = (0..ell as u32).collect();
        another_permutation.shuffle(&mut rng);

        // Let's start mutating the instances of the verifier to see that the proof fails
        assert!(shuffle_proof
            .verify(&crs, &vec_S, &vec_R, &vec_T, &vec_U, &M, &mut rng)
            .is_err());

        // apply a different permutation than the one proved
        assert!(shuffle_proof
            .verify(
                &crs,
                &vec_R,
                &vec_S,
                &get_permutation(&vec_T, &another_permutation),
                &get_permutation(&vec_U, &another_permutation),
                &M,
                &mut rng
            )
            .is_err());

        // provide wrong perm commitment
        assert!(shuffle_proof
            .verify(&crs, &vec_R, &vec_S, &vec_T, &vec_U, &M.mul(k), &mut rng)
            .is_err());

        // instnace outputs use a different randomizer
        let another_k = Fr::rand(&mut rng);
        let another_vec_T: Vec<G1Affine> = vec_T
            .iter()
            .map(|T| T.mul(another_k).into_affine())
            .collect();
        let another_vec_U: Vec<G1Affine> = vec_U
            .iter()
            .map(|U| U.mul(another_k).into_affine())
            .collect();
        assert!(shuffle_proof
            .verify(
                &crs,
                &vec_R,
                &vec_S,
                &another_vec_T,
                &another_vec_U,
                &M,
                &mut rng
            )
            .is_err());
    }
}

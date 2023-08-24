#![allow(non_snake_case)]
use std::ops::Mul;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{batch_inversion, Field, One};
use ark_serialize::Read;
use ark_serialize::SerializationError;
use ark_serialize::Write;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;

use crate::transcript::CurdleproofsTranscript;
use crate::util::deserialize_g1projective_vec;
use crate::util::serialize_g1projective_vec;
use merlin::Transcript;

use crate::errors::ProofError;
use crate::msm_accumulator::MsmAccumulator;
use crate::util::{
    generate_blinders, get_verification_scalars_bitstring, msm, msm_from_projective,
};

/// A $SameMsm$ proof object
#[derive(Clone, Debug)]
pub struct SameMultiscalarProof {
    B_a: G1Projective,
    B_t: G1Projective,
    B_u: G1Projective,

    vec_L_A: Vec<G1Projective>,
    vec_L_T: Vec<G1Projective>,
    vec_L_U: Vec<G1Projective>,
    vec_R_A: Vec<G1Projective>,
    vec_R_T: Vec<G1Projective>,
    vec_R_U: Vec<G1Projective>,

    x_final: Fr,
}

impl SameMultiscalarProof {
    /// Create a $SameMsm$ proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{G}$ CRS vector
    /// * `A` - commitment to `vec_x` under `crs_G_vec`
    /// * `Z_t` - commitment to `vec_x` under `vec_T`
    /// * `Z_u` - commitment to `vec_x` under `vec_U`
    /// * `vec_T` - base points $\bm{T}$
    /// * `vec_U` - base points $\bm{U}$
    /// * `vec_x` - scalar vector (*witness*)
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: RngCore>(
        mut crs_G_vec: Vec<G1Affine>,

        A: G1Projective,
        Z_t: G1Projective,
        Z_u: G1Projective,
        mut vec_T: Vec<G1Affine>,
        mut vec_U: Vec<G1Affine>,

        mut vec_x: Vec<Fr>,

        transcript: &mut Transcript,
        rng: &mut T,
    ) -> SameMultiscalarProof {
        let mut n = vec_x.len();
        let lg_n = ark_std::log2(n) as usize;

        let mut vec_L_T = Vec::with_capacity(lg_n);
        let mut vec_R_T = Vec::with_capacity(lg_n);
        let mut vec_L_U = Vec::with_capacity(lg_n);
        let mut vec_R_U = Vec::with_capacity(lg_n);
        let mut vec_L_A = Vec::with_capacity(lg_n);
        let mut vec_R_A = Vec::with_capacity(lg_n);

        let vec_r: Vec<Fr> = generate_blinders(rng, n);

        let B_a = msm(&crs_G_vec, &vec_r);
        let B_t = msm(&vec_T, &vec_r);
        let B_u = msm(&vec_U, &vec_r);

        transcript.append_list(b"same_msm_step1", &[&A, &Z_t, &Z_u]);
        transcript.append_list(b"same_msm_step1", &[&vec_T, &vec_U]);
        transcript.append_list(b"same_msm_step1", &[&B_a, &B_t, &B_u]);
        let alpha = transcript.get_and_append_challenge(b"same_msm_alpha");

        for i in 0..n {
            vec_x[i] = vec_r[i] + (alpha * vec_x[i]);
        }

        let mut slice_x = &mut vec_x[..];
        let mut slice_T = &mut vec_T[..];
        let mut slice_U = &mut vec_U[..];
        let mut slice_G = &mut crs_G_vec[..];

        // Step 2: log(n) rounds of recursion
        while slice_x.len() > 1 {
            n /= 2;

            let (x_L, x_R) = slice_x.split_at_mut(n);
            let (T_L, T_R) = slice_T.split_at_mut(n);
            let (U_L, U_R) = slice_U.split_at_mut(n);
            let (G_L, G_R) = slice_G.split_at_mut(n);

            let L_A = msm(G_R, x_L);
            let L_T = msm(T_R, x_L);
            let L_U = msm(U_R, x_L);
            let R_A = msm(G_L, x_R);
            let R_T = msm(T_L, x_R);
            let R_U = msm(U_L, x_R);

            vec_L_A.push(L_A);
            vec_L_T.push(L_T);
            vec_L_U.push(L_U);
            vec_R_A.push(R_A);
            vec_R_T.push(R_T);
            vec_R_U.push(R_U);

            transcript.append_list(b"same_msm_loop", &[&L_A, &L_T, &L_U, &R_A, &R_T, &R_U]);
            let gamma = transcript.get_and_append_challenge(b"same_msm_gamma");
            let gamma_inv = gamma.inverse().expect("gamma must have an inverse");

            // Fold vectors and basis
            for i in 0..n {
                x_L[i] += gamma_inv * x_R[i];
                T_L[i] = (T_L[i] + T_R[i].mul(gamma)).into_affine();
                U_L[i] = (U_L[i] + U_R[i].mul(gamma)).into_affine();
                G_L[i] = (G_L[i] + G_R[i].mul(gamma)).into_affine();
            }
            slice_x = x_L;
            slice_T = T_L;
            slice_U = U_L;
            slice_G = G_L;
        }

        SameMultiscalarProof {
            B_a,
            B_t,
            B_u,
            vec_L_A,
            vec_L_T,
            vec_L_U,
            vec_R_A,
            vec_R_T,
            vec_R_U,
            x_final: slice_x[0],
        }
    }

    /// Generate verification scalars for the $SameMsm$ [verifier optimization](crate::notes::optimizations)
    #[allow(clippy::type_complexity)]
    fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(Vec<Fr>, Vec<Fr>, Vec<Fr>), ProofError> {
        let lg_n = self.vec_L_A.len();
        if lg_n >= 32 {
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        let bitstring = get_verification_scalars_bitstring(n, lg_n);

        // 1. Recompute x_k,...,x_1 based on the proof transcript
        let mut challenges: Vec<Fr> = Vec::with_capacity(lg_n);
        for i in 0..self.vec_L_A.len() {
            transcript.append_list(
                b"same_msm_loop",
                &[
                    &self.vec_L_A[i],
                    &self.vec_L_T[i],
                    &self.vec_L_U[i],
                    &self.vec_R_A[i],
                    &self.vec_R_T[i],
                    &self.vec_R_U[i],
                ],
            );
            challenges.push(transcript.get_and_append_challenge(b"same_msm_gamma"));
        }

        // 2. Compute 1/(x_k...x_1) and 1/x_k, ..., 1/x_1
        let mut challenges_inv: Vec<Fr> = challenges.clone();
        batch_inversion(&mut challenges_inv);

        // 3. Compute s values using the bitstring
        let mut vec_s: Vec<Fr> = Vec::with_capacity(n);
        for i in 0..n {
            vec_s.push(Fr::one());
            for j in 0..bitstring[i].len() {
                vec_s[i] *= challenges[bitstring[i][j]]
            }
        }

        Ok((challenges, challenges_inv, vec_s))
    }

    /// Verify a $SameMsm$ proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{G}$ CRS vector
    /// * `A` - commitment to `vec_x` under `crs_G_vec`
    /// * `Z_t` - commitment to `vec_x` under `vec_T`
    /// * `Z_u` - commitment to `vec_x` under `vec_U`
    /// * `vec_T` - base points $\bm{T}$
    /// * `vec_U` - base points $\bm{U}$
    #[allow(clippy::too_many_arguments)]
    pub fn verify<T: RngCore>(
        &self,
        crs_G_vec: &[G1Affine],

        A: G1Projective,
        Z_t: G1Projective,
        Z_u: G1Projective,
        vec_T: &Vec<G1Affine>,
        vec_U: &Vec<G1Affine>,

        transcript: &mut Transcript,
        msm_accumulator: &mut MsmAccumulator,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        let n = vec_T.len();

        // Step 1
        transcript.append_list(b"same_msm_step1", &[&A, &Z_t, &Z_u]);
        transcript.append_list(b"same_msm_step1", &[vec_T, vec_U]);
        transcript.append_list(b"same_msm_step1", &[&self.B_a, &self.B_t, &self.B_u]);
        let alpha = transcript.get_and_append_challenge(b"same_msm_alpha");

        // Step 2
        let (vec_gamma, vec_gamma_inv, vec_s) = self.verification_scalars(n, transcript)?;

        // Cmopute vector x*vec_s for the right-hand-side
        let vec_x_times_s: Vec<Fr> = vec_s.iter().map(|s_i| self.x_final * *s_i).collect();

        // Step 3
        let A_a = self.B_a + A.mul(alpha);
        let Z_t_a = self.B_t + Z_t.mul(alpha);
        let Z_u_a = self.B_u + Z_u.mul(alpha);

        let point_lhs = msm_from_projective(&self.vec_L_A, &vec_gamma)
            + A_a
            + msm_from_projective(&self.vec_R_A, &vec_gamma_inv);
        msm_accumulator.accumulate_check(&point_lhs, &vec_x_times_s, crs_G_vec, rng);

        let point_lhs = msm_from_projective(&self.vec_L_T, &vec_gamma)
            + Z_t_a
            + msm_from_projective(&self.vec_R_T, &vec_gamma_inv);
        msm_accumulator.accumulate_check(&point_lhs, &vec_x_times_s, vec_T, rng);

        let point_lhs = msm_from_projective(&self.vec_L_U, &vec_gamma)
            + Z_u_a
            + msm_from_projective(&self.vec_R_U, &vec_gamma_inv);
        msm_accumulator.accumulate_check(&point_lhs, &vec_x_times_s, vec_U, rng);
        Ok(())
    }

    pub fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
        self.B_a.serialize_compressed(&mut w)?;
        self.B_t.serialize_compressed(&mut w)?;
        self.B_u.serialize_compressed(&mut w)?;
        serialize_g1projective_vec(&self.vec_L_A, &mut w)?;
        serialize_g1projective_vec(&self.vec_L_T, &mut w)?;
        serialize_g1projective_vec(&self.vec_L_U, &mut w)?;
        serialize_g1projective_vec(&self.vec_R_A, &mut w)?;
        serialize_g1projective_vec(&self.vec_R_T, &mut w)?;
        serialize_g1projective_vec(&self.vec_R_U, &mut w)?;
        self.x_final.serialize_compressed(&mut w)?;
        Ok(())
    }
    pub fn deserialize<R: Read>(mut r: R, log2_n: usize) -> Result<Self, SerializationError> {
        Ok(Self {
            B_a: G1Projective::deserialize_compressed(&mut r)?,
            B_t: G1Projective::deserialize_compressed(&mut r)?,
            B_u: G1Projective::deserialize_compressed(&mut r)?,
            vec_L_A: deserialize_g1projective_vec(&mut r, log2_n)?,
            vec_L_T: deserialize_g1projective_vec(&mut r, log2_n)?,
            vec_L_U: deserialize_g1projective_vec(&mut r, log2_n)?,
            vec_R_A: deserialize_g1projective_vec(&mut r, log2_n)?,
            vec_R_T: deserialize_g1projective_vec(&mut r, log2_n)?,
            vec_R_U: deserialize_g1projective_vec(&mut r, log2_n)?,
            x_final: Fr::deserialize_compressed(&mut r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
    use ark_std::UniformRand;
    use core::iter;

    #[test]
    fn test_same_msm_argument() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut transcript_prover = merlin::Transcript::new(b"same_msm");

        let n = 128;

        let crs_G_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(n)
            .collect();

        let vec_T: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(n)
            .collect();
        let vec_U: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(n)
            .collect();

        let vec_x: Vec<Fr> = iter::repeat_with(|| rng.gen()).take(n).collect();

        let A = msm(&crs_G_vec, &vec_x);
        let Z_t = msm(&vec_T, &vec_x);
        let Z_u = msm(&vec_U, &vec_x);

        let proof = SameMultiscalarProof::new(
            crs_G_vec.clone(),
            A.clone(),
            Z_t.clone(),
            Z_u.clone(),
            vec_T.clone(),
            vec_U.clone(),
            vec_x,
            &mut transcript_prover,
            &mut rng,
        );

        // Reset the FS
        let mut transcript_verifier = merlin::Transcript::new(b"same_msm");
        let mut msm_accumulator = MsmAccumulator::new();

        assert!(proof
            .verify(
                &crs_G_vec,
                A,
                Z_t,
                Z_u,
                &vec_T,
                &vec_U,
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());

        assert!(msm_accumulator.verify().is_ok())
    }
}

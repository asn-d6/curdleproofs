#![allow(non_snake_case)]
use std::ops::Mul;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{batch_inversion, Field};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use ark_std::{One, Zero};

use merlin::Transcript;

use crate::errors::ProofError;
use crate::msm_accumulator::MsmAccumulator;
use crate::transcript::CurdleproofsTranscript;
use crate::util::{
    generate_blinders, get_verification_scalars_bitstring, inner_product, msm, msm_from_projective,
};

/// An IPA proof object
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct InnerProductProof {
    B_c: G1Projective,
    B_d: G1Projective,

    vec_L_C: Vec<G1Projective>,
    vec_R_C: Vec<G1Projective>,
    vec_L_D: Vec<G1Projective>,
    vec_R_D: Vec<G1Projective>,

    c_final: Fr,
    d_final: Fr,
}

/// Generate two blinder vectors `r` and `z` that satisfy the following constraints:
///    <r, d> + <z, c> == 0
/// ^  <r, z> == 0
///
/// We do this by solving a system of two equations over two unknowns.
fn generate_ipa_blinders<T: RngCore>(rng: &mut T, c: &Vec<Fr>, d: &[Fr]) -> (Vec<Fr>, Vec<Fr>) {
    let n = c.len();

    // Generate all the blinders but leave out two blinders from z
    let r: Vec<Fr> = generate_blinders(rng, n);
    let mut z: Vec<Fr> = generate_blinders(rng, n - 2); // leave two out

    // We have to solve a system of two linear equations over the two unknowns: z_{n-1} and z_n (the two blinders we left out)
    // Consider first equation: <r, d> + <z, c> == 0
    // <=> r_1 * d_1 + ... + r_n * d_n + z_1 * c_1 + ... + z_{n-1} * c_{n-1} + z_n * c_n == 0
    // The last two products contain the unknowns whereas all the previous is a known quantity `omega` -- let's compute it below
    let omega = inner_product(&r, d) + inner_product(&z[..n - 2], &c[..n - 2]);
    // Now let's consider the second equation: <r, z> == 0
    // <=> r_1 * z_1 + ... r_{n-1} * z_{n-1} * r_n * z_n == 0
    // Again, the last two products contain the unknowns whereas all the previous is a known quantity `delta` -- let's compute it below
    let delta = inner_product(&r[..n - 2], &z[..n - 2]);

    // Solving the first equation for z_{n-1} we get:
    //
    //   z_{n-1} = - c_{n-1}^-1 (z_n * c_n + omega)
    //
    // then plugging the above z_{n-1} into the second equation, we get:
    //
    //   z_n = (r_{n-1} * c_{n-1}^-1 * omega - delta) / (- r_{n-1} * c_{n-1}^-1 * c_n + r_{n-1})
    //
    // We compute these values below:

    let inv_c = c[n - 2].inverse().unwrap(); // save c_{n-1}^-1 for later
    let last_z = (r[n - 2] * inv_c * omega - delta)
        * (-r[n - 2] * inv_c * c[n - 1] + r[n - 1]).inverse().unwrap();
    let penultimate_z = -inv_c * (last_z * c[n - 1] + omega);

    z.push(penultimate_z);
    z.push(last_z);

    // Make sure the constraints were satisfied
    debug_assert!(inner_product(&r, d) + inner_product(&z, c) == Fr::zero());
    debug_assert!(inner_product(&r, &z) == Fr::zero());

    (r, z)
}

impl InnerProductProof {
    /// Create an inner product proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{G}$ CRS vector
    /// * `crs_G_prime_vec` - $\bm{G'}$ CRS blinder vector
    /// * `crs_H` - $H$ CRS element
    /// * `C` - commitment to `vec_c`
    /// * `D` - commitment to `vec_d`
    /// * `z` - inner product result
    /// * `vec_c` - first inner product vector (*witness*)
    /// * `vec_d` - second inner product vector (*witness*)
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: RngCore>(
        mut crs_G_vec: Vec<G1Affine>,
        mut crs_G_prime_vec: Vec<G1Affine>,
        crs_H: &G1Projective,

        C: G1Projective,
        D: G1Projective,
        z: Fr,

        mut vec_c: Vec<Fr>,
        mut vec_d: Vec<Fr>,

        transcript: &mut Transcript,
        rng: &mut T,
    ) -> InnerProductProof {
        let mut n = vec_c.len();
        let lg_n = ark_std::log2(n) as usize;
        assert_eq!(vec_d.len(), n);
        assert!(n.is_power_of_two());

        let mut vec_L_C = Vec::with_capacity(lg_n);
        let mut vec_R_C = Vec::with_capacity(lg_n);
        let mut vec_L_D = Vec::with_capacity(lg_n);
        let mut vec_R_D = Vec::with_capacity(lg_n);

        // Step 1
        let (vec_r_c, vec_r_d) = generate_ipa_blinders(rng, &vec_c, &vec_d);

        let B_c = msm(&crs_G_vec, &vec_r_c);
        let B_d = msm(&crs_G_prime_vec, &vec_r_d);

        transcript.append_list(b"ipa_step1", &[&C, &D]);
        transcript.append(b"ipa_step1", &z);
        transcript.append_list(b"ipa_step1", &[&B_c, &B_d]);
        let alpha = transcript.get_and_append_challenge(b"ipa_alpha");
        let beta = transcript.get_and_append_challenge(b"ipa_beta");

        // Rewrite vectors c and d
        for i in 0..n {
            vec_c[i] = vec_r_c[i] + alpha * vec_c[i];
            vec_d[i] = vec_r_d[i] + alpha * vec_d[i];
        }
        let H = crs_H.mul(beta);

        // Step 2
        // Create slices backed by their respective vectors.  This lets us reslice as we compress the lengths of the
        // vectors in the main loop below.
        let mut slice_G = &mut crs_G_vec[..];
        let mut slice_G_prime = &mut crs_G_prime_vec[..];
        let mut slice_c = &mut vec_c[..];
        let mut slice_d = &mut vec_d[..];

        while slice_c.len() > 1 {
            n /= 2;

            let (c_L, c_R) = slice_c.split_at_mut(n);
            let (d_L, d_R) = slice_d.split_at_mut(n);
            let (G_L, G_R) = slice_G.split_at_mut(n);
            let (G_prime_L, G_prime_R) = slice_G_prime.split_at_mut(n);

            let L_C = msm(G_R, c_L) + H.mul(inner_product(c_L, d_R));
            let L_D = msm(G_prime_L, d_R);
            let R_C = msm(G_L, c_R) + H.mul(inner_product(c_R, d_L));
            let R_D = msm(G_prime_R, d_L);

            // Append elements to the proof
            vec_L_C.push(L_C);
            vec_L_D.push(L_D);
            vec_R_C.push(R_C);
            vec_R_D.push(R_D);

            transcript.append_list(b"ipa_loop", &[&L_C, &L_D, &R_C, &R_D]);
            let gamma = transcript.get_and_append_challenge(b"ipa_gamma");
            let gamma_inv = gamma.inverse().expect("gamma must have an inverse");

            // Fold input vectors and basis
            for i in 0..n {
                c_L[i] += gamma_inv * c_R[i];
                d_L[i] += gamma * d_R[i];
                G_L[i] = (G_L[i] + G_R[i].mul(gamma)).into_affine();
                G_prime_L[i] = (G_prime_L[i] + G_prime_R[i].mul(gamma_inv)).into_affine();
            }

            // Save the rescaled vector for splitting in the next loop
            slice_c = c_L;
            slice_d = d_L;
            slice_G = G_L;
            slice_G_prime = G_prime_L;
        }

        InnerProductProof {
            B_c,
            B_d,
            vec_L_C,
            vec_R_C,
            vec_L_D,
            vec_R_D,
            c_final: slice_c[0],
            d_final: slice_d[0],
        }
    }

    /// Generate verification scalars for the IPA [verifier optimization](crate::notes::optimizations#ipa-verification-scalars)
    #[allow(clippy::type_complexity)]
    fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>), ProofError> {
        let lg_n = self.vec_L_C.len();
        if lg_n >= 32 {
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        let verification_scalars_bitstring = get_verification_scalars_bitstring(n, lg_n);

        // 1. Recompute gamma_k,...,gamma_1 based on the proof transcript
        let mut challenges: Vec<Fr> = Vec::with_capacity(lg_n);
        for i in 0..self.vec_L_C.len() {
            transcript.append_list(
                b"ipa_loop",
                &[
                    &self.vec_L_C[i],
                    &self.vec_L_D[i],
                    &self.vec_R_C[i],
                    &self.vec_R_D[i],
                ],
            );
            challenges.push(transcript.get_and_append_challenge(b"ipa_gamma"));
        }

        // 2. Compute 1/gamma_k, ..., 1/gamma_1
        let mut challenges_inv: Vec<Fr> = challenges.clone();
        batch_inversion(&mut challenges_inv);

        // 3. Compute s values by iterating over the bitstring
        let mut vec_s: Vec<Fr> = Vec::with_capacity(n);
        for i in 0..n {
            vec_s.push(Fr::one());
            for j in 0..verification_scalars_bitstring[i].len() {
                vec_s[i] *= challenges[verification_scalars_bitstring[i][j]]
            }
        }

        // 4. Also compute 1/s vector
        let mut vec_inv_s = vec_s.clone();
        batch_inversion(&mut vec_inv_s);

        Ok((challenges, challenges_inv, vec_s, vec_inv_s))
    }

    /// Verify an inner product proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_vec` - $\bm{G}$ CRS vector
    /// * `crs_G_prime_vec` - $\bm{G'}$ CRS blinder vector
    /// * `crs_H` - $H$ CRS element
    /// * `C` - commitment to witness vector `vec_c`
    /// * `D` - commitment to witness vector `vec_d`
    /// * `z` - inner product result
    /// * `vec_u` - Auxiliary vector for verifier [optimization](crate::notes::optimizations#grandproduct-verifier-optimizations)
    #[allow(clippy::too_many_arguments)]
    pub fn verify<T: RngCore>(
        &self,
        crs_G_vec: &Vec<G1Affine>,
        crs_H: &G1Projective,

        C: G1Projective, // no need for mut
        D: G1Projective,
        z: Fr,
        vec_u: Vec<Fr>,

        transcript: &mut Transcript,
        msm_accumulator: &mut MsmAccumulator,

        rng: &mut T,
    ) -> Result<(), ProofError> {
        let n = crs_G_vec.len();
        assert!(n.is_power_of_two());

        // Step 1:
        transcript.append_list(b"ipa_step1", &[&C, &D]);
        transcript.append(b"ipa_step1", &z);
        transcript.append_list(b"ipa_step1", &[&self.B_c, &self.B_d]);
        let alpha = transcript.get_and_append_challenge(b"ipa_alpha");
        let beta = transcript.get_and_append_challenge(b"ipa_beta");

        // Step 2
        let (vec_gamma, vec_gamma_inv, vec_s, vec_inv_s) =
            self.verification_scalars(n, transcript)?;

        // Get vector of c*s_i for first accumulated check
        let vec_c_times_s: Vec<Fr> = vec_s.iter().map(|s_i| self.c_final * *s_i).collect();

        let mut vec_rhs_scalars = vec_c_times_s; // collect right-hand-side scalars of first check
        vec_rhs_scalars.push(self.c_final * self.d_final * beta);
        let mut vec_G_H = crs_G_vec.clone(); // collect right-hand-side points of first check
        vec_G_H.push(crs_H.into_affine());

        // Step 3
        let H = crs_H.mul(beta);
        let C_a = self.B_c + C.mul(alpha) + H.mul(alpha * alpha * z);

        let point_lhs = msm_from_projective(&self.vec_L_C, &vec_gamma)
            + C_a
            + msm_from_projective(&self.vec_R_C, &vec_gamma_inv);

        msm_accumulator.accumulate_check(&point_lhs, &vec_rhs_scalars, &vec_G_H, rng);

        // Get vector of d*((1/s_i) * u_i) for the second accumulated check
        let vec_d_div_s: Vec<Fr> = vec_inv_s
            .into_iter()
            .zip(vec_u)
            .map(|(s_inv_i, u_i)| self.d_final * (s_inv_i * u_i))
            .collect();

        let D_a = self.B_d + D.mul(alpha);
        let point_lhs = msm_from_projective(&self.vec_L_D, &vec_gamma)
            + D_a
            + msm_from_projective(&self.vec_R_D, &vec_gamma_inv);

        msm_accumulator.accumulate_check(&point_lhs, &vec_d_div_s, crs_G_vec, rng);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
    use ark_std::UniformRand;
    use core::iter;

    use crate::msm_accumulator::MsmAccumulator;

    #[test]
    fn test_inner_product_argument() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut transcript_prover = merlin::Transcript::new(b"IPA");

        let n = 128;

        let crs_G_vec: Vec<G1Affine> =
            iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
                .take(n)
                .collect();
        // There is actually a relationship between crs_G_vec and crs_G_prime_vec because of the grandproduct optimization
        // We generate a `vec_u` which has the discrete logs of every crs_G_prime element with respect to crs_G
        let vec_u = generate_blinders(&mut rng, n);
        let crs_G_prime_vec: Vec<G1Affine> = crs_G_vec
            .iter()
            .zip(&vec_u)
            .map(|(G_i, u_i)| G_i.mul(*u_i).into_affine())
            .collect();
        let crs_H = G1Projective::rand(&mut rng);

        // Generate some random vectors
        let vec_b: Vec<Fr> = iter::repeat_with(|| rng.gen()).take(n).collect();
        let vec_c: Vec<Fr> = iter::repeat_with(|| rng.gen()).take(n).collect();

        let z = inner_product(&vec_b, &vec_c);

        // Create commitments
        let B = msm(&crs_G_vec, &vec_b);
        let C = msm(&crs_G_prime_vec, &vec_c);

        let proof = InnerProductProof::new(
            crs_G_vec.clone(),
            crs_G_prime_vec.clone(),
            &crs_H,
            B.clone(),
            C.clone(),
            z,
            vec_b.clone(),
            vec_c.clone(),
            &mut transcript_prover,
            &mut rng,
        );

        // Reset the FS
        let mut transcript_verifier = merlin::Transcript::new(b"IPA");
        let mut msm_accumulator = MsmAccumulator::new();

        assert!(proof
            .verify(
                &crs_G_vec,
                &crs_H,
                B,
                C,
                z,
                vec_u.clone(),
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());

        assert!(msm_accumulator.verify().is_ok());

        ////////////////////////////////////////////////////
        // Let's also try a basic bad proof test where we provide the wrong inner product result to the verifeir
        let mut transcript_verifier = merlin::Transcript::new(b"IPA");
        let mut msm_accumulator = MsmAccumulator::new();

        assert!(proof
            .verify(
                &crs_G_vec,
                &crs_H,
                B,
                C,
                z + Fr::one(),
                vec_u,
                &mut transcript_verifier,
                &mut msm_accumulator,
                &mut rng,
            )
            .is_ok());

        assert!(msm_accumulator.verify().is_err());
    }

    #[test]
    fn test_inner_product() {
        let a = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let b = vec![
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ];
        assert_eq!(Fr::from(40u64), inner_product(&a, &b));
    }
}

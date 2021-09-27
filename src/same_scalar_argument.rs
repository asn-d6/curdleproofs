#![allow(non_snake_case)]

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use crate::commitments::GroupCommitment;
use crate::errors::ProofError;
use crate::transcript::CurdleproofsTranscript;
use merlin::Transcript;

#[derive(Clone, Debug)]
pub struct SameScalarProof {
    cm_A: GroupCommitment,
    cm_B: GroupCommitment,
    z_k: Fr,
    z_t: Fr,
    z_u: Fr,
}

impl SameScalarProof {
    /// Create a SameScalar proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_t` - CRS group element $G_t$
    /// * `crs_G_u` - CRS group element $G_u$
    /// * `crs_H` - CRS group element $H$
    /// * `R`, `S` - instance group elements $R$ and $S$
    /// * `cm_T`, `cm_U` - instance commitments $cm_t$ and $cm_u$
    /// * `k` - "same scalar" witness
    /// * `r_t` - randomness of $cm_t$
    /// * `r_u` - randomness of $cm_u$
    pub fn new<T: RngCore>(
        crs_G_t: &G1Projective,
        crs_G_u: &G1Projective,
        crs_H: &G1Projective,

        R: G1Projective,
        S: G1Projective,
        cm_T: GroupCommitment,
        cm_U: GroupCommitment,
        k: Fr,
        r_t: Fr,
        r_u: Fr,

        transcript: &mut Transcript,
        rng: &mut T,
    ) -> SameScalarProof {
        // Step 1
        let r_a = Fr::rand(rng);
        let r_b = Fr::rand(rng);
        let r_k = Fr::rand(rng);

        let cm_A = GroupCommitment::new(crs_G_t, crs_H, R.mul(r_k.into_repr()), r_a);
        let cm_B = GroupCommitment::new(crs_G_u, crs_H, S.mul(r_k.into_repr()), r_b);

        transcript.append_list(
            b"sameexp_points",
            &[
                &R, &S, &cm_T.T_1, &cm_T.T_2, &cm_U.T_1, &cm_U.T_2, &cm_A.T_1, &cm_A.T_2,
                &cm_B.T_1, &cm_B.T_2,
            ],
        );
        let alpha = transcript.get_and_append_challenge(b"same_scalar_alpha");

        // Step 2
        let z_k = r_k + k * alpha;
        let z_t = r_a + r_t * alpha;
        let z_u = r_b + r_u * alpha;

        SameScalarProof {
            cm_A,
            cm_B,
            z_k,
            z_t,
            z_u,
        }
    }

    /// Verify a same scalar proof
    ///
    /// # Arguments
    ///
    /// * `crs_G_t` - CRS group element $G_t$
    /// * `crs_G_u` - CRS group element $G_u$
    /// * `crs_H` - CRS group element $H$
    /// * `R`, `S` - instance group elements $R$ and $S$
    /// * `cm_T`, `cm_U` - instance commitments $cm_t$ and $cm_u$
    pub fn verify(
        &self,

        crs_G_t: &G1Projective,
        crs_G_u: &G1Projective,
        crs_H: &G1Projective,

        R: G1Projective,
        S: G1Projective,
        cm_T: GroupCommitment,
        cm_U: GroupCommitment,

        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        // Step 1
        transcript.append_list(
            b"sameexp_points",
            &[
                &R,
                &S,
                &cm_T.T_1,
                &cm_T.T_2,
                &cm_U.T_1,
                &cm_U.T_2,
                &self.cm_A.T_1,
                &self.cm_A.T_2,
                &self.cm_B.T_1,
                &self.cm_B.T_2,
            ],
        );
        let alpha = transcript.get_and_append_challenge(b"same_scalar_alpha");

        // Step 2
        let expected_1 =
            GroupCommitment::new(crs_G_t, crs_H, R.mul(self.z_k.into_repr()), self.z_t);
        let expected_2 =
            GroupCommitment::new(crs_G_u, crs_H, S.mul(self.z_k.into_repr()), self.z_u);

        if (self.cm_A + cm_T * alpha == expected_1) && (self.cm_B + cm_U * alpha == expected_2) {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_same_scalar_argument() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut transcript_prover = merlin::Transcript::new(b"same_scalar");

        let crs_G_t = G1Projective::rand(&mut rng);
        let crs_G_u = G1Projective::rand(&mut rng);
        let crs_H = G1Projective::rand(&mut rng);

        let R = G1Projective::rand(&mut rng);
        let S = G1Projective::rand(&mut rng);

        let k = Fr::rand(&mut rng);
        let r_t = Fr::rand(&mut rng);
        let r_u = Fr::rand(&mut rng);

        let cm_T = GroupCommitment::new(&crs_G_t, &crs_H, R.mul(k.into_repr()), r_t);
        let cm_U = GroupCommitment::new(&crs_G_u, &crs_H, S.mul(k.into_repr()), r_u);

        let proof = SameScalarProof::new(
            &crs_G_t,
            &crs_G_u,
            &crs_H,
            R,
            S,
            cm_T,
            cm_U,
            k,
            r_t,
            r_u,
            &mut transcript_prover,
            &mut rng,
        );

        // Reset the FS
        let mut transcript_verifier = merlin::Transcript::new(b"same_scalar");
        assert!(proof
            .verify(
                &crs_G_t,
                &crs_G_u,
                &crs_H,
                R,
                S,
                cm_T,
                cm_U,
                &mut transcript_verifier
            )
            .is_ok());
    }
}

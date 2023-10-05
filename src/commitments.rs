//! # GroupCommitment commitment scheme
//!
//! We implement the following commitment scheme which allows us to commit to a group element $T$:
//!
//! $GroupCommitment( (G_T, H); \\ T; \\ r_T) = com_T = (com_{T,1}, com_{T,2}) = ( r_T G_T, \\ T + r_T H)$
//!
//! This commitment scheme is statistically binding and hiding under the DDH assumption.
//! It is also equipped with a homomorphism such that
//!
//! \\[
//! \begin{align*}
//! & GroupCommitment( (G_T, H); \ A; \ r_{A}) + GroupCommit( (G_T, H); \ B; \ r_{B})  \\\\
//! & \hspace{8cm}  =
//! GroupCommitment( (G_T, H); \ A + B; \ r_{A} + r_{B}) \\\\
//! & \hspace{8cm} =
//! ( (r_A + r_B) G_T, \ (A + B) + (r_A + r_B) H)
//! \end{align*}
//! \\]
//!
//! It is based on the ElGamal encryption scheme.

#![allow(non_snake_case)]

use ark_bls12_381::{Fr, G1Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use std::ops::{Add, Mul};

/// A GroupCommitment object
///
/// $GroupCommitment((G , H); T ; r ) = cm_T = (cm_{T,1} , cm_{T,2} ) = (r G , T + r H)$
#[derive(Copy, Clone, CanonicalDeserialize, CanonicalSerialize, Debug, PartialEq, Eq)]
pub struct GroupCommitment {
    /// Given $GroupCommitment((G , H); T ; r )$ this is $rG$
    pub T_1: G1Projective,
    /// Given $GroupCommitment((G , H); T ; r )$ this is $T + rH$
    pub T_2: G1Projective,
}

impl GroupCommitment {
    /// Commit to `T` using provided CRS and randomness `r`
    pub fn new(
        crs_G: &G1Projective,
        crs_H: &G1Projective,
        T: G1Projective,
        r: Fr,
    ) -> GroupCommitment {
        let T_1 = crs_G.mul(&r);
        let T_2 = T + crs_H.mul(&r);

        GroupCommitment { T_1, T_2 }
    }
}

// Teach the machine how to add commitments
impl Add<GroupCommitment> for GroupCommitment {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            T_1: self.T_1 + other.T_1,
            T_2: self.T_2 + other.T_2,
        }
    }
}

// Teach the machine how to multiply commitments
impl Mul<Fr> for GroupCommitment {
    type Output = Self;

    fn mul(self, other: Fr) -> Self {
        Self {
            T_1: self.T_1.mul(&other),
            T_2: self.T_2.mul(&other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;

    #[test]
    fn test_group_commit() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let crs_G = G1Projective::rand(&mut rng);
        let crs_H = G1Projective::rand(&mut rng);

        let A = G1Projective::rand(&mut rng);
        let B = G1Projective::rand(&mut rng);

        let r_a = Fr::rand(&mut rng);
        let r_b = Fr::rand(&mut rng);

        let cm_a = GroupCommitment::new(&crs_G, &crs_H, A, r_a);
        let cm_b = GroupCommitment::new(&crs_G, &crs_H, B, r_b);
        let cm_a_b = GroupCommitment::new(&crs_G, &crs_H, A + B, r_a + r_b);

        // Check that the commitment is homomorphic
        assert_eq!(cm_a + cm_b, cm_a_b);
    }
}

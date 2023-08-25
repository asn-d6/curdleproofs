//! Accumulate all MSMs into a giant MSM and verify them all at the end to [amortize costs](crate::notes::optimizations#msm-accumulator).
//!
//! <center><img width="70%" src="https://github.com/asn-d6/curdleproofs/raw/backup/doc/images/accumulator.png"></img></center>
//!
//! Code adapted from [jellyfish](https://github.com/EspressoSystems/jellyfish/blob/main/plonk/src/proof_system/structs.rs#L865).

#![allow(non_snake_case)]

use std::ops::Mul;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_std::rand::RngCore;
use ark_std::{UniformRand, Zero};

use hashbrown::HashMap;

use crate::errors::ProofError;
use crate::util::msm;

/// An MSM accumulator object
#[derive(Default, Clone)]
pub struct MsmAccumulator {
    A_c: G1Projective,
    base_scalar_map: HashMap<G1Affine, Fr>,
}

impl MsmAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            A_c: G1Projective::zero(),

            base_scalar_map: HashMap::new(),
        }
    }

    /// Accumulate the check $C = \bm{x} \times \bm{V}$
    pub fn accumulate_check<T: RngCore>(
        &mut self,
        C: &G1Projective,
        vec_x: &[Fr],
        vec_V: &[G1Affine],
        rng: &mut T,
    ) {
        let random_factor = Fr::rand(rng); // `a` in the paper

        self.A_c += C.mul(&random_factor);

        for (scalar, base) in vec_x.iter().zip(vec_V.iter()) {
            let entry_scalar = self.base_scalar_map.entry(*base).or_insert_with(Fr::zero);
            *entry_scalar += random_factor * scalar;
        }
    }

    /// Verify all checks accumulated on this MSM accumulator
    pub fn verify(self) -> Result<(), ProofError> {
        let mut bases = vec![];
        let mut scalars = vec![];
        for (base, scalar) in &self.base_scalar_map {
            bases.push(*base);
            scalars.push(*scalar);
        }

        if (msm(&bases, &scalars) - self.A_c).is_zero() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use core::iter;

    use crate::util::generate_blinders;

    #[test]
    fn test_msm_accumulator() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let n = 4;

        // Let's check that $B == <vec_B, vec_a> ^ D == <vec_D, vec_c>$
        let vec_B: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(n)
            .collect();
        let vec_a = generate_blinders(&mut rng, n);
        let B = msm(&vec_B, &vec_a);

        let vec_D: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(n)
            .collect();
        let vec_c = generate_blinders(&mut rng, n);
        let D = msm(&vec_D, &vec_c);

        let mut msm_accumulator = MsmAccumulator::new();

        msm_accumulator.accumulate_check(&B, &vec_a, &vec_B, &mut rng);
        msm_accumulator.accumulate_check(&D, &vec_c, &vec_D, &mut rng);

        assert!(msm_accumulator.verify().is_ok());
    }
}

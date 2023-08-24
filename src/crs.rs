#![allow(non_snake_case)]
pub use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::UniformRand;

use core::iter;

use crate::util::sum_affine_points;
use crate::whisk::{from_bytes_g1affine, to_bytes_g1affine};
use crate::N_BLINDERS;

/// crs_H, crs_G_t, crs_G_u
pub const CRS_EXTRA_POINTS: usize = 3;

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

impl CurdleproofsCrs {
    pub fn from_points(ell: usize, points: &[G1Affine]) -> Result<Self, String> {
        let n = ell + N_BLINDERS;
        let num_points = n + CRS_EXTRA_POINTS;
        if points.len() < num_points {
            return Err("not enough points".to_owned());
        }

        let vec_G = points[0..ell].to_vec();
        let vec_H = points[ell..n].to_vec();
        let G_sum = sum_affine_points(&vec_G);
        let H_sum = sum_affine_points(&vec_H);

        Ok(Self {
            vec_G,
            vec_H,
            H: points[n].into(),
            G_t: points[n + 1].into(),
            G_u: points[n + 2].into(),
            G_sum,
            H_sum,
        })
    }

    /// Generate a randomly generated (unsafe) CRS
    pub fn generate_crs(ell: usize) -> Self {
        let num_points = ell + N_BLINDERS + CRS_EXTRA_POINTS;
        let mut rng = StdRng::seed_from_u64(0u64);

        let points = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(num_points)
            .collect::<Vec<_>>();
        CurdleproofsCrs::from_points(ell, &points).expect("unexpected points len")
    }

    pub fn log2_n(&self) -> usize {
        let n = self.vec_H.len() + self.vec_G.len();
        (n as f64).log2().ceil() as usize
    }
}

type G1AffineHex = String;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CurdleproofsCrsHex {
    pub vec_G: Vec<G1AffineHex>,
    pub vec_H: Vec<G1AffineHex>,
    pub H: G1AffineHex,
    pub G_t: G1AffineHex,
    pub G_u: G1AffineHex,
    pub G_sum: G1AffineHex,
    pub H_sum: G1AffineHex,
}

impl TryFrom<&CurdleproofsCrs> for CurdleproofsCrsHex {
    type Error = SerializationError;
    fn try_from(value: &CurdleproofsCrs) -> Result<Self, Self::Error> {
        Ok(Self {
            vec_G: to_hex_g1affine_vec(&value.vec_G)?,
            vec_H: to_hex_g1affine_vec(&value.vec_H)?,
            H: to_hex_g1affine(&value.H.into())?,
            G_t: to_hex_g1affine(&value.G_t.into())?,
            G_u: to_hex_g1affine(&value.G_u.into())?,
            G_sum: to_hex_g1affine(&value.G_sum)?,
            H_sum: to_hex_g1affine(&value.H_sum)?,
        })
    }
}

impl TryInto<CurdleproofsCrs> for &CurdleproofsCrsHex {
    type Error = SerializationError;
    fn try_into(self) -> Result<CurdleproofsCrs, Self::Error> {
        Ok(CurdleproofsCrs {
            vec_G: from_hex_g1affine_vec(&self.vec_G)?,
            vec_H: from_hex_g1affine_vec(&self.vec_H)?,
            H: from_hex_g1affine(&self.H)?.into(),
            G_t: from_hex_g1affine(&self.G_t)?.into(),
            G_u: from_hex_g1affine(&self.G_u)?.into(),
            G_sum: from_hex_g1affine(&self.G_sum)?,
            H_sum: from_hex_g1affine(&self.H_sum)?,
        })
    }
}

fn to_hex_g1affine_vec(v: &[G1Affine]) -> Result<Vec<String>, SerializationError> {
    v.iter().map(to_hex_g1affine).collect()
}

fn from_hex_g1affine_vec(v: &[String]) -> Result<Vec<G1Affine>, SerializationError> {
    v.iter().map(|p| from_hex_g1affine(p)).collect()
}

fn to_hex_g1affine(p: &G1Affine) -> Result<String, SerializationError> {
    Ok(format!("0x{}", hex::encode(to_bytes_g1affine(p)?)))
}

fn from_hex_g1affine(s: &str) -> Result<G1Affine, SerializationError> {
    let s = s
        .strip_prefix("0x")
        .ok_or(SerializationError::InvalidData)?;
    from_bytes_g1affine(
        &hex::decode(s)
            .map_err(|_| SerializationError::InvalidData)?
            .try_into()
            .map_err(|_| SerializationError::InvalidData)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_crs_json() {
        let crs = CurdleproofsCrs::generate_crs(64 - N_BLINDERS);
        let crs_json: CurdleproofsCrsHex = (&crs).try_into().unwrap();
        let crs_json_str = serde_json::to_string(&crs_json).unwrap();

        let from_crs_json: CurdleproofsCrsHex = serde_json::from_str(&crs_json_str).unwrap();
        assert_eq!(from_crs_json, crs_json);
        let from_crs: CurdleproofsCrs = (&from_crs_json).try_into().unwrap();
        assert_eq!(from_crs.H_sum, crs.H_sum);
    }
}

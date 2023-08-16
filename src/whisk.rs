#![allow(non_snake_case)]
pub use ark_bls12_381::g1::G1_GENERATOR_X;
pub use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::AffineCurve;
use ark_ff::{PrimeField, ToBytes};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::prelude::SliceRandom;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

use crate::{
    curdleproofs::{CurdleproofsCrs, CurdleproofsProof},
    transcript::CurdleproofsTranscript,
    util::shuffle_permute_and_commit_input,
    N_BLINDERS,
};

pub const FIELD_ELEMENT_SIZE: usize = 32;
pub const G1POINT_SIZE: usize = 48;
pub const WHISK_SHUFFLE_PROOF_SIZE: usize = 4576;
// 48+48+32
pub const TRACKER_PROOF_SIZE: usize = 128;

// TODO: Customize
const N: usize = 128;
const ELL: usize = N - N_BLINDERS;

pub type WhiskShuffleProofBytes = [u8; WHISK_SHUFFLE_PROOF_SIZE];
pub type TrackerProofBytes = [u8; TRACKER_PROOF_SIZE];
pub type FieldElementBytes = [u8; FIELD_ELEMENT_SIZE];
pub type G1PointBytes = [u8; G1POINT_SIZE];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhiskTracker {
    #[serde(with = "hex::serde")]
    pub r_G: G1PointBytes, // r * G
    #[serde(with = "hex::serde")]
    pub k_r_G: G1PointBytes, // k * r * G
}

/// A tracker proof object
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TrackerProof {
    A: G1Projective,
    B: G1Projective,
    s: Fr,
}

/// Convenience wrapper for whisk verifiers
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct WhiskShuffleProof {
    M: G1Projective,
    proof: CurdleproofsProof,
}

/// Verify a whisk shuffle proof
///
/// # Arguments
///
/// * `crs`                       - Curdleproofs CRS (Common Reference String), a trusted setup
/// * `pre_trackers`              - Trackers before shuffling
/// * `post_trackers`             - Trackers after shuffling
/// * `whisk_shuffle_proof_bytes` - Serialized Whisk shuffle proof
pub fn is_valid_whisk_shuffle_proof<T: RngCore>(
    rng: &mut T,
    crs: &CurdleproofsCrs,
    pre_trackers: &[WhiskTracker],
    post_trackers: &[WhiskTracker],
    whisk_shuffle_proof_bytes: &WhiskShuffleProofBytes,
) -> Result<bool, SerializationError> {
    let (vec_r, vec_s) = unzip_trackers(pre_trackers)?;
    let (vec_t, vec_u) = unzip_trackers(post_trackers)?;
    let whisk_shuffle_proof =
        WhiskShuffleProof::deserialize(Cursor::new(whisk_shuffle_proof_bytes))?;

    Ok(whisk_shuffle_proof
        .proof
        .verify(
            crs,
            &vec_r,
            &vec_s,
            &vec_t,
            &vec_u,
            &whisk_shuffle_proof.M,
            rng,
        )
        .is_ok())
}

/// Create a whisk shuffle proof and serialize it for Whisk
///
/// # Arguments
///
/// * `crs`          - Curdleproofs CRS (Common Reference String), a trusted setup
/// * `pre_trackers` - Whisk trackers to shuffle
///
/// # Returns
///
/// A tuple containing
/// * `0` `post_trackers`             - Resulting shuffled trackers
/// * `1` `whisk_shuffle_proof_bytes` - Serialized whisk shuffle proof
pub fn generate_whisk_shuffle_proof<T: RngCore>(
    rng: &mut T,
    crs: &CurdleproofsCrs,
    pre_trackers: &[WhiskTracker],
) -> Result<(Vec<WhiskTracker>, WhiskShuffleProofBytes), SerializationError> {
    // Get witnesses: the permutation, the randomizer, and a bunch of blinders
    let mut permutation: Vec<u32> = (0..ELL as u32).collect();

    // permutation and k (randomizer) can be forgotten immediately after creating the proof
    permutation.shuffle(rng);
    let k = Fr::rand(rng);

    // Get shuffle inputs
    let (vec_r, vec_s) = unzip_trackers(pre_trackers)?;

    let (vec_t, vec_u, m, vec_m_blinders) =
        shuffle_permute_and_commit_input(crs, &vec_r, &vec_s, &permutation, &k, rng);

    let proof = CurdleproofsProof::new(
        crs,
        vec_r.clone(),
        vec_s.clone(),
        vec_t.clone(),
        vec_u.clone(),
        m,
        permutation.clone(),
        k,
        vec_m_blinders,
        rng,
    );

    let mut whisk_shuffle_proof_bytes = [0; WHISK_SHUFFLE_PROOF_SIZE];
    WhiskShuffleProof { proof, M: m }.serialize(whisk_shuffle_proof_bytes.as_mut_slice())?;

    Ok((zip_trackers(&vec_t, &vec_u)?, whisk_shuffle_proof_bytes))
}

/// Verify knowledge of `k` such that `tracker.k_r_g == k * tracker.r_g` and `k_commitment == k * BLS_G1_GENERATOR`.
/// Defined in <https://github.com/nalinbhardwaj/curdleproofs.pie/blob/59eb1d54fe193f063a718fc3bdded4734e66bddc/curdleproofs/curdleproofs/whisk_interface.py#L48-L68>
pub fn is_valid_whisk_tracker_proof(
    tracker: &WhiskTracker,
    k_commitment: &G1PointBytes,
    tracker_proof: &TrackerProofBytes,
) -> Result<bool, SerializationError> {
    let tracker_proof = deserialize_tracker_proof(tracker_proof)?;

    // TODO: deserializing here to serialize immediately after in append_list()
    //       serde could be avoided but there's value in checking point's ok before proof gen
    let k_r_G = from_bytes_g1affine(&tracker.k_r_G)?;
    let r_G = from_bytes_g1affine(&tracker.r_G)?;
    let k_G = from_bytes_g1affine(k_commitment)?;
    let G = G1Affine::prime_subgroup_generator();

    // `k_r_G`: Existing WhiskTracker.k_r_g
    // `r_G`: Existing WhiskTracker.k_r_g
    // `k_G`: Existing k commitment
    // `G`: Generator point, omit as is public knowledge
    // `A`: From py impl `A = multiply(G, int(blinder))`
    // `B`: From py impl `B = multiply(r_G, int(blinder))`
    // `s`: From py impl `s = blinder - challenge * k`

    let mut transcript = Transcript::new(b"whisk_opening_proof");

    // TODO: Check points before creating proof?
    transcript.append_list(
        b"tracker_opening_proof",
        [
            &k_G,
            &G1Affine::prime_subgroup_generator(),
            &k_r_G,
            &r_G,
            &G1Affine::from(tracker_proof.A),
            &G1Affine::from(tracker_proof.B),
        ]
        .as_slice(),
    );
    let challenge = transcript.get_and_append_challenge(b"tracker_opening_proof_challenge");

    let A_prime = G.mul(tracker_proof.s) + k_G.mul(challenge);
    let B_prime = r_G.mul(tracker_proof.s) + k_r_G.mul(challenge);

    Ok(A_prime == tracker_proof.A && B_prime == tracker_proof.B)
}

pub fn generate_whisk_tracker_proof<T: RngCore>(
    rng: &mut T,
    tracker: &WhiskTracker,
    k: &Fr,
) -> Result<TrackerProofBytes, SerializationError> {
    let k_r_g = from_bytes_g1affine(&tracker.k_r_G)?;
    let r_g = from_bytes_g1affine(&tracker.r_G)?;
    let G = G1Affine::prime_subgroup_generator();

    let k_G = G.mul(*k);
    let blinder = Fr::rand(rng);
    let A = G.mul(blinder);
    let B = r_g.mul(blinder);

    let mut transcript = Transcript::new(b"whisk_opening_proof");

    transcript.append_list(
        b"tracker_opening_proof",
        [
            &G1Affine::from(k_G),
            &G,
            &k_r_g,
            &r_g,
            &G1Affine::from(A),
            &G1Affine::from(B),
        ]
        .as_slice(),
    );

    let challenge = transcript.get_and_append_challenge(b"tracker_opening_proof_challenge");
    let s = blinder - challenge * k;

    let tracker_proof = TrackerProof { A, B, s };

    serialize_tracker_proof(&tracker_proof)
}

fn unzip_trackers(
    trackers: &[WhiskTracker],
) -> Result<(Vec<G1Affine>, Vec<G1Affine>), SerializationError> {
    let vec_r: Vec<G1Affine> = trackers
        .iter()
        .map(|tracker| from_bytes_g1affine(&tracker.r_G))
        .collect::<Result<_, _>>()?;
    let vec_s: Vec<G1Affine> = trackers
        .iter()
        .map(|tracker| from_bytes_g1affine(&tracker.k_r_G))
        .collect::<Result<_, _>>()?;
    Ok((vec_r, vec_s))
}

fn zip_trackers(
    vec_r: &[G1Affine],
    vec_s: &[G1Affine],
) -> Result<Vec<WhiskTracker>, SerializationError> {
    vec_r
        .iter()
        .zip(vec_s.iter())
        .map(|(r_G, k_r_G)| {
            Ok(WhiskTracker {
                r_G: to_bytes_g1affine(r_G)?,
                k_r_G: to_bytes_g1affine(k_r_G)?,
            })
        })
        .collect::<Result<_, _>>()
}

fn serialize_tracker_proof(proof: &TrackerProof) -> Result<TrackerProofBytes, SerializationError> {
    let mut out = [0; TRACKER_PROOF_SIZE];
    proof.serialize(out.as_mut_slice())?;
    Ok(out)
}

fn deserialize_tracker_proof(
    proof_bytes: &TrackerProofBytes,
) -> Result<TrackerProof, SerializationError> {
    TrackerProof::deserialize(Cursor::new(proof_bytes))
}

pub fn to_bytes_g1affine(g1: &G1Affine) -> Result<G1PointBytes, SerializationError> {
    let mut out = [0; G1POINT_SIZE];
    g1.serialize(out.as_mut_slice())?;
    Ok(out)
}

pub fn from_bytes_g1affine(buf: &G1PointBytes) -> Result<G1Affine, SerializationError> {
    G1Affine::deserialize(Cursor::new(buf))
}

/// Returns G1 generator (x,y)
pub fn g1_generator() -> G1Affine {
    G1Affine::prime_subgroup_generator()
}

/// G1 scalar multiplication
pub fn bls_g1_scalar_multiply(g1: &G1Affine, scalar: &Fr) -> G1Affine {
    G1Affine::from(g1.mul(*scalar))
}

/// Rand scalar
pub fn rand_scalar<T: RngCore>(rng: &mut T) -> Fr {
    Fr::rand(rng)
}

/// Serialize field element to bytes
pub fn to_bytes_fr(fr: &Fr) -> FieldElementBytes {
    let mut bytes = [0u8; FIELD_ELEMENT_SIZE];
    fr.write(&mut bytes[..]).unwrap();
    bytes
}

/// Convert bytes to a BLS field scalar. The output is not uniform over the BLS field.
///
/// Reads bytes in big-endian, and converts them to a field element.
/// If the bytes are larger than the modulus, it will reduce them.
pub fn from_bytes_fr(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curdleproofs::generate_crs;
    use ark_ff::One;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use core::iter;

    #[test]
    fn serde_fr_rand() {
        let k_bytes =
            hex::decode("9ebde6d84a58debe5ef02c729366a76078a15a653aa6234aeab6996ce47f8d2a")
                .unwrap();
        let k = from_bytes_fr(&k_bytes);
        assert_eq!(to_bytes_fr(&k).as_slice(), &k_bytes);
    }

    #[test]
    fn serde_g1_rand() {
        let p_bytes = hex::decode("6d4761a01a6aa320db42b47ebe47b1fb7f7ab3925c4b1a2c6de3a15e40976596cad444ea4216d467d297ad2081107192").unwrap();
        let p = from_bytes_g1affine(&p_bytes.clone().try_into().unwrap()).unwrap();
        assert_eq!(to_bytes_g1affine(&p).unwrap().as_slice(), &p_bytes);
    }

    fn compute_tracker(k: &Fr, r: &Fr) -> Result<WhiskTracker, SerializationError> {
        let G = G1Affine::prime_subgroup_generator();

        let r_G = G.mul(*r);
        let k_r_G = G1Affine::from(r_G).mul(*k);

        Ok(WhiskTracker {
            r_G: to_bytes_g1affine(&G1Affine::from(r_G))?,
            k_r_G: to_bytes_g1affine(&G1Affine::from(k_r_G))?,
        })
    }

    fn generate_tracker<T: RngCore>(
        rng: &mut T,
        k: &Fr,
    ) -> Result<WhiskTracker, SerializationError> {
        // r can be forgotten
        let r = Fr::rand(rng);
        compute_tracker(k, &r)
    }

    fn get_k_commitment(k: &Fr) -> Result<G1PointBytes, SerializationError> {
        let G = G1Affine::prime_subgroup_generator();
        to_bytes_g1affine(&G1Affine::from(G.mul(*k)))
    }

    fn generate_shuffle_trackers<T: RngCore>(
        rng: &mut T,
    ) -> Result<Vec<WhiskTracker>, SerializationError> {
        iter::repeat_with(|| {
            let k = Fr::rand(rng);
            generate_tracker(rng, &k)
        })
        .take(ELL)
        .collect()
    }

    #[test]
    fn whisk_tracker_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let k = Fr::rand(&mut rng);
        let tracker = generate_tracker(&mut rng, &k).unwrap();
        let k_commitment = get_k_commitment(&k).unwrap();

        let tracker_proof = generate_whisk_tracker_proof(&mut rng, &tracker, &k).unwrap();
        assert!(is_valid_whisk_tracker_proof(&tracker, &k_commitment, &tracker_proof).unwrap());

        // Assert correct TRACKER_PROOF_SIZE
        let mut out_data = vec![];
        let mut out = Cursor::new(&mut out_data);
        deserialize_tracker_proof(&tracker_proof)
            .unwrap()
            .serialize(&mut out)
            .unwrap();
        assert_eq!(out_data.len(), TRACKER_PROOF_SIZE);
    }

    #[derive(Serialize, Deserialize)]
    struct ShuffleProofSpec {
        pre_trackers: Vec<WhiskTracker>,
        post_trackers: Vec<WhiskTracker>,
        #[serde(with = "hex::serde")]
        proof: Vec<u8>,
    }

    fn shuffle_proof_fixture(n: usize) -> String {
        format!("tests/fixtures/shuffle_proof_{}_valid.yml", n)
    }

    #[test]
    fn whisk_shuffle_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crs: CurdleproofsCrs = generate_crs(ELL);

        let shuffled_trackers = generate_shuffle_trackers(&mut rng).unwrap();

        let (whisk_post_shuffle_trackers, whisk_shuffle_proof_bytes) =
            generate_whisk_shuffle_proof(&mut rng, &crs, &shuffled_trackers).unwrap();
        assert!(is_valid_whisk_shuffle_proof(
            &mut rng,
            &crs,
            &shuffled_trackers,
            &whisk_post_shuffle_trackers,
            &whisk_shuffle_proof_bytes
        )
        .unwrap());

        // Assert correct TRACKER_PROOF_SIZE
        let mut out_data = vec![];
        let mut out = Cursor::new(&mut out_data);
        WhiskShuffleProof::deserialize(Cursor::new(&whisk_shuffle_proof_bytes))
            .unwrap()
            .serialize(&mut out)
            .unwrap();
        assert_eq!(out_data.len(), WHISK_SHUFFLE_PROOF_SIZE);

        if std::env::var("GENERATE_VECTORS").is_ok() {
            let shuffle_proof_spec = ShuffleProofSpec {
                pre_trackers: shuffled_trackers.clone(),
                post_trackers: whisk_post_shuffle_trackers.clone(),
                proof: whisk_shuffle_proof_bytes.to_vec(),
            };

            let file = std::fs::File::create(shuffle_proof_fixture(N)).unwrap();
            serde_yaml::to_writer(file, &shuffle_proof_spec).unwrap();
        }
    }

    // Construct the CRS

    struct Block {
        pub whisk_opening_proof: TrackerProofBytes,
        pub whisk_post_shuffle_trackers: Vec<WhiskTracker>,
        pub whisk_shuffle_proof: WhiskShuffleProofBytes,
        pub whisk_registration_proof: TrackerProofBytes,
        pub whisk_tracker: WhiskTracker,
        pub whisk_k_commitment: G1PointBytes,
    }

    struct State {
        pub proposer_tracker: WhiskTracker,
        pub proposer_k_commitment: G1PointBytes,
        pub shuffled_trackers: Vec<WhiskTracker>,
    }

    fn process_block(crs: &CurdleproofsCrs, state: &mut State, block: &Block) {
        let mut rng = StdRng::seed_from_u64(0u64);

        // process_whisk_opening_proof
        assert!(
            is_valid_whisk_tracker_proof(
                &state.proposer_tracker,
                &state.proposer_k_commitment,
                &block.whisk_opening_proof,
            )
            .unwrap(),
            "invalid whisk_opening_proof"
        );

        // whisk_process_shuffled_trackers
        assert!(
            is_valid_whisk_shuffle_proof(
                &mut rng,
                &crs,
                &state.shuffled_trackers,
                &block.whisk_post_shuffle_trackers,
                &block.whisk_shuffle_proof
            )
            .unwrap(),
            "invalid whisk_shuffle_proof"
        );

        // whisk_process_tracker_registration
        let G = to_bytes_g1affine(&G1Affine::prime_subgroup_generator()).unwrap();
        if state.proposer_tracker.r_G == G {
            // First proposal
            assert!(
                is_valid_whisk_tracker_proof(
                    &block.whisk_tracker,
                    &block.whisk_k_commitment,
                    &block.whisk_registration_proof,
                )
                .unwrap(),
                "invalid whisk_registration_proof"
            );
            state.proposer_tracker = block.whisk_tracker.clone();
            state.proposer_k_commitment = block.whisk_k_commitment;
        } else {
            // Next proposals, registration data not used
        }
    }

    fn produce_block(
        crs: &CurdleproofsCrs,
        state: &State,
        proposer_k: &Fr,
        proposer_index: u64,
    ) -> Block {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (whisk_post_shuffle_trackers, whisk_shuffle_proof) =
            generate_whisk_shuffle_proof(&mut rng, &crs, &state.shuffled_trackers).unwrap();

        let is_first_proposal = state.proposer_tracker.r_G
            == to_bytes_g1affine(&G1Affine::prime_subgroup_generator()).unwrap();

        let (whisk_registration_proof, whisk_tracker, whisk_k_commitment) = if is_first_proposal {
            // First proposal, validator creates tracker for registering
            let whisk_tracker = generate_tracker(&mut rng, &proposer_k).unwrap();
            let whisk_k_commitment = get_k_commitment(&proposer_k).unwrap();
            let whisk_registration_proof =
                generate_whisk_tracker_proof(&mut rng, &whisk_tracker, &proposer_k).unwrap();
            (whisk_registration_proof, whisk_tracker, whisk_k_commitment)
        } else {
            // And subsequent proposals leave registration fields empty
            let whisk_registration_proof = [0; TRACKER_PROOF_SIZE];
            let whisk_tracker = compute_tracker(&Fr::one(), &Fr::one()).unwrap();
            let whisk_k_commitment = get_k_commitment(&Fr::one()).unwrap();
            (whisk_registration_proof, whisk_tracker, whisk_k_commitment)
        };

        let k_prev_proposal = if is_first_proposal {
            // On first proposal the k is computed deterministically and known to all
            compute_initial_k(proposer_index)
        } else {
            // Subsequent proposals use same k for registered tracker
            *proposer_k
        };

        let whisk_opening_proof =
            generate_whisk_tracker_proof(&mut rng, &state.proposer_tracker, &k_prev_proposal)
                .unwrap();

        Block {
            whisk_opening_proof,
            whisk_post_shuffle_trackers,
            whisk_shuffle_proof,
            whisk_registration_proof,
            whisk_tracker,
            whisk_k_commitment,
        }
    }

    fn compute_initial_k(index: u64) -> Fr {
        from_bytes_fr(&index.to_be_bytes())
    }

    #[test]
    fn whisk_full_lifecycle() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crs: CurdleproofsCrs = generate_crs(ELL);

        // Initial tracker in state
        let shuffled_trackers: Vec<WhiskTracker> = iter::repeat_with(|| {
            let k = Fr::rand(&mut rng);
            generate_tracker(&mut rng, &k)
        })
        .take(ELL)
        .collect::<Result<_, _>>()
        .unwrap();

        let proposer_index = 15400;
        let proposer_initial_k = compute_initial_k(proposer_index);

        // Initial dummy values, r = 1
        let mut state = State {
            proposer_tracker: compute_tracker(&proposer_initial_k, &Fr::one()).unwrap(),
            proposer_k_commitment: get_k_commitment(&proposer_initial_k).unwrap(),
            shuffled_trackers,
        };

        // k must be kept
        let proposer_k = Fr::rand(&mut rng);

        // On first proposal, validator creates tracker for registering
        let block_0 = produce_block(&crs, &state, &proposer_k, proposer_index);
        // Block is valid
        process_block(&crs, &mut state, &block_0);

        // On second proposal, validator opens previously submited tracker
        let block_1 = produce_block(&crs, &state, &proposer_k, proposer_index);
        // Block is valid
        process_block(&crs, &mut state, &block_1);
    }
}

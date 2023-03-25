#![allow(non_snake_case)]
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::prelude::SliceRandom;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use std::io::Cursor;

use crate::{
    curdleproofs::{CurdleproofsCrs, CurdleproofsProof},
    util::shuffle_permute_and_commit_input,
    N_BLINDERS,
};

const G1POINT_SIZE: usize = 48;
const SHUFFLE_PROOF_SIZE: usize = 1024;
const TRACKER_PROOF_SIZE: usize = 1024;

// TODO: Customize
const N: usize = 64;
const ELL: usize = N - N_BLINDERS;

pub type G1PointBytes = [u8; G1POINT_SIZE];
pub type ShuffleProofBytes = [u8; SHUFFLE_PROOF_SIZE];
pub type TrackerProofBytes = [u8; TRACKER_PROOF_SIZE];

pub struct WhiskTracker {
    pub r_g: G1PointBytes,   // r * G
    pub k_r_g: G1PointBytes, // k * r * G
}

/// A tracker proof object
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TrackerProof {
    k_G: G1Projective,
    // TODO: Is the generator necessary to include in the proof?
    G: G1Projective,
    A: G1Projective,
    B: G1Projective,
    s: G1Projective,
}

/// Verify a whisk shuffle proof
///
/// # Arguments
///
/// * `crs`           - Curdleproofs CRS (Common Reference String), a trusted setup
/// * `pre_trackers`  - Trackers before shuffling
/// * `post_trackers` - Trackers after shuffling
/// * `m`             - Commitment to secret permutation
/// * `shuffle_proof` - Shuffle proof struct
pub fn is_valid_whisk_shuffle_proof<T: RngCore>(
    rng: &mut T,
    crs: &CurdleproofsCrs,
    pre_trackers: &Vec<WhiskTracker>,
    post_trackers: &Vec<WhiskTracker>,
    m: &G1PointBytes,
    shuffle_proof: &ShuffleProofBytes,
) -> Result<(), Box<dyn std::error::Error>> {
    let (vec_r, vec_s) = deserialize_trackers(pre_trackers)?;
    let (vec_t, vec_u) = deserialize_trackers(post_trackers)?;
    let m_projective = G1Projective::from(deserialize_g1_point(m)?);
    let shuffle_proof_instance = deserialize_shuffle_proof(shuffle_proof)?;

    shuffle_proof_instance.verify(crs, &vec_r, &vec_s, &vec_t, &vec_u, &m_projective, rng)?;

    Ok(())
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
/// * `0` `post_trackers` - Resulting shuffled trackers
/// * `1` `m`             - Commitment to secret permutation
/// * `2` `shuffle_proof` - Shuffle proof struct
pub fn generate_whisk_shuffle_proof<T: RngCore>(
    rng: &mut T,
    crs: &CurdleproofsCrs,
    pre_trackers: &Vec<WhiskTracker>,
) -> Result<(Vec<WhiskTracker>, G1PointBytes, ShuffleProofBytes), Box<dyn std::error::Error>> {
    // Get witnesses: the permutation, the randomizer, and a bunch of blinders
    let mut permutation: Vec<u32> = (0..ELL as u32).collect();

    // permutation and k (randomizer) can be forgotten immediately after creating the proof
    permutation.shuffle(rng);
    let k = Fr::rand(rng);

    // Get shuffle inputs
    let (vec_r, vec_s) = deserialize_trackers(pre_trackers)?;

    let (vec_t, vec_u, m, vec_m_blinders) =
        shuffle_permute_and_commit_input(crs, &vec_r, &vec_s, &permutation, &k, rng);

    let shuffle_proof_instance = CurdleproofsProof::new(
        crs,
        vec_r.clone(),
        vec_s.clone(),
        vec_t.clone(),
        vec_u.clone(),
        m,
        permutation.clone(),
        k,
        vec_m_blinders.clone(),
        rng,
    );

    let mut shuffle_proof: Vec<u8> = vec![];
    shuffle_proof_instance.serialize(&mut shuffle_proof)?;

    Ok((
        serialize_trackers(&vec_t, &vec_u)?,
        serialize_g1_point(&G1Affine::from(m))?,
        serialize_shuffle_proof(&shuffle_proof_instance)?,
    ))
}

/// Verify knowledge of `k` such that `tracker.k_r_g == k * tracker.r_g` and `k_commitment == k * BLS_G1_GENERATOR`.
/// Defined in https://github.com/nalinbhardwaj/curdleproofs.pie/blob/59eb1d54fe193f063a718fc3bdded4734e66bddc/curdleproofs/curdleproofs/whisk_interface.py#L48-L68
pub fn is_valid_whisk_tracker_proof(
    crs: &CurdleproofsCrs,
    tracker: &WhiskTracker,
    k_commitment: &G1PointBytes,
    tracker_proof: &TrackerProofBytes,
) -> Result<(), Box<dyn std::error::Error>> {
    let tracker_proof = deserialize_tracker_proof(tracker_proof)?;

    // `k_r_G`: Existing WhiskTracker.k_r_g
    // `r_G`: Existing WhiskTracker.k_r_g
    // `k_G`: ?? provided externally, k commitment?
    // `G`: Generator point, known by all not necessary
    // `A`: From python implementation `A = multiply(G, int(blinder))`
    // `B`: From python implementation `B = multiply(r_G, int(blinder))`
    // `s`: From python implementation `s = blinder - challenge * k`

    // challenge = transcript.get_and_append_challenge(
    //     b"tracker_opening_proof_challenge"
    // )
    //
    // Aprime = add(multiply(self.G, int(self.s)), multiply(self.k_G, int(challenge)))
    // Bprime = add(
    //     multiply(self.r_G, int(self.s)), multiply(self.k_r_G, int(challenge))
    // )
    //
    // return eq(Aprime, self.A) and eq(Bprime, self.B)

    todo!("wisk");
}

pub fn generate_whisk_tracker_proof(
    crs: &CurdleproofsCrs,
    tracker: &WhiskTracker,
    k_G: G1Projective,
    G: G1Projective,
    k: Fr,
) -> Result<TrackerProofBytes, Box<dyn std::error::Error>> {
    let k_r_g = tracker.k_r_g;
    let r_g = tracker.r_g;

    // blinder = generate_blinders(1)[0]
    // A = multiply(G, int(blinder))
    // B = multiply(r_G, int(blinder))

    // transcript.append_list(
    //     b"tracker_opening_proof",
    //     points_projective_to_bytes([k_G, G, k_r_G, r_G, A, B]),
    // )

    // challenge = transcript.get_and_append_challenge(
    //     b"tracker_opening_proof_challenge"
    // )
    // s = blinder - challenge * k

    todo!("whisk");
}

fn deserialize_g1_point(g1_point: &G1PointBytes) -> Result<G1Affine, SerializationError> {
    G1Affine::deserialize(Cursor::new(g1_point))
}

fn serialize_g1_point(g1_point: &G1Affine) -> Result<G1PointBytes, SerializationError> {
    let mut out = [0; 48];
    g1_point.serialize(out.as_mut_slice())?;
    Ok(out)
}

fn deserialize_trackers(
    trackers: &Vec<WhiskTracker>,
) -> Result<(Vec<G1Affine>, Vec<G1Affine>), SerializationError> {
    let vec_r: Result<Vec<G1Affine>, SerializationError> = trackers
        .iter()
        .map(|tracker| deserialize_g1_point(&tracker.r_g))
        .collect();
    let vec_s: Result<Vec<G1Affine>, SerializationError> = trackers
        .iter()
        .map(|tracker| deserialize_g1_point(&tracker.k_r_g))
        .collect();
    Ok((vec_r?, vec_s?))
}

fn serialize_trackers(
    vec_r: &Vec<G1Affine>,
    vec_s: &Vec<G1Affine>,
) -> Result<Vec<WhiskTracker>, SerializationError> {
    let trackers: Result<Vec<WhiskTracker>, SerializationError> = vec_r
        .into_iter()
        .zip(vec_s.into_iter())
        .map(|(r_g, k_r_g)| {
            Ok(WhiskTracker {
                r_g: serialize_g1_point(r_g)?,
                k_r_g: serialize_g1_point(k_r_g)?,
            })
        })
        .collect();
    Ok(trackers?)
}

fn serialize_tracker_proof(proof: &TrackerProof) -> Result<TrackerProofBytes, SerializationError> {
    let mut out = [0u8; TRACKER_PROOF_SIZE];
    proof.serialize(out.as_mut_slice())?;
    Ok(out)
}

fn deserialize_tracker_proof(
    proof_bytes: &TrackerProofBytes,
) -> Result<TrackerProof, SerializationError> {
    TrackerProof::deserialize(Cursor::new(proof_bytes))
}

fn serialize_shuffle_proof(
    proof: &CurdleproofsProof,
) -> Result<ShuffleProofBytes, SerializationError> {
    let mut out = [0u8; SHUFFLE_PROOF_SIZE];
    proof.serialize(out.as_mut_slice())?;
    Ok(out)
}

fn deserialize_shuffle_proof(
    proof_bytes: &ShuffleProofBytes,
) -> Result<CurdleproofsProof, SerializationError> {
    CurdleproofsProof::deserialize(Cursor::new(proof_bytes))
}

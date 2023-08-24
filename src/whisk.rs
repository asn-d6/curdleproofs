#![allow(non_snake_case)]
pub use ark_bls12_381::g1::G1_GENERATOR_X;
pub use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::prelude::SliceRandom;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::ops::Mul;

use crate::crs::CurdleproofsCrs;
use crate::{
    curdleproofs::CurdleproofsProof, transcript::CurdleproofsTranscript,
    util::shuffle_permute_and_commit_input, N_BLINDERS,
};

pub const FIELD_ELEMENT_SIZE: usize = 32;
pub const G1POINT_SIZE: usize = 48;
pub const WHISK_SHUFFLE_PROOF_SIZE: usize = 4496;
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

impl WhiskTracker {
    pub fn from_k_r(k: &Fr, r: &Fr) -> Result<Self, SerializationError> {
        let G = G1Affine::generator();

        let r_G = G.mul(*r);
        let k_r_G = G1Affine::from(r_G).mul(*k);

        Ok(WhiskTracker {
            r_G: to_bytes_g1affine(&G1Affine::from(r_G))?,
            k_r_G: to_bytes_g1affine(&G1Affine::from(k_r_G))?,
        })
    }

    pub fn from_k<T: RngCore>(rng: &mut T, k: &Fr) -> Result<Self, SerializationError> {
        WhiskTracker::from_k_r(k, &Fr::rand(rng))
    }

    pub fn from_rand<T: RngCore>(rng: &mut T) -> Result<Self, SerializationError> {
        let k = Fr::rand(rng);
        WhiskTracker::from_k(rng, &k)
    }
}

/// A tracker proof object
/// CanonicalSerde produces compact representation since they type has no dyn vecs
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TrackerProof {
    A: G1Projective,
    B: G1Projective,
    s: Fr,
}

/// Convenience wrapper for whisk verifiers
#[derive(Clone, Debug)]
pub struct WhiskShuffleProof {
    M: G1Projective,
    proof: CurdleproofsProof,
}

impl WhiskShuffleProof {
    pub fn serialize<W: Write>(&self, mut w: W) -> Result<(), SerializationError> {
        self.M.serialize_compressed(&mut w)?;
        self.proof.serialize(&mut w)?;
        Ok(())
    }

    pub fn deserialize<R: Read>(mut r: R, log2_n: usize) -> Result<Self, SerializationError> {
        Ok(Self {
            M: G1Projective::deserialize_compressed(&mut r)?,
            proof: CurdleproofsProof::deserialize(&mut r, log2_n)?,
        })
    }
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
        WhiskShuffleProof::deserialize(Cursor::new(whisk_shuffle_proof_bytes), crs.log2_n())?;

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
    let G = G1Affine::generator();

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
            &G1Affine::generator(),
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
    let G = G1Affine::generator();

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
    proof.serialize_compressed(out.as_mut_slice())?;
    Ok(out)
}

fn deserialize_tracker_proof(
    proof_bytes: &TrackerProofBytes,
) -> Result<TrackerProof, SerializationError> {
    TrackerProof::deserialize_compressed(Cursor::new(proof_bytes))
}

pub fn to_bytes_g1affine(g1: &G1Affine) -> Result<G1PointBytes, SerializationError> {
    let mut out = [0; G1POINT_SIZE];
    g1.serialize_compressed(out.as_mut_slice())?;
    Ok(out)
}

pub fn from_bytes_g1affine(buf: &G1PointBytes) -> Result<G1Affine, SerializationError> {
    G1Affine::deserialize_compressed(Cursor::new(buf))
}

/// Returns G1 generator (x,y)
pub fn g1_generator() -> G1Affine {
    G1Affine::generator()
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
pub fn to_bytes_fr(fr: &Fr) -> Result<FieldElementBytes, SerializationError> {
    let mut out = [0u8; FIELD_ELEMENT_SIZE];
    fr.serialize_uncompressed(&mut out[..])?;
    Ok(out)
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
    use ark_ff::One;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn serde_fr_rand() {
        let k_bytes =
            hex::decode("9ebde6d84a58debe5ef02c729366a76078a15a653aa6234aeab6996ce47f8d2a")
                .unwrap();
        let k = from_bytes_fr(&k_bytes);
        assert_eq!(to_bytes_fr(&k).unwrap().as_slice(), &k_bytes);
    }

    #[test]
    fn serde_g1_roundtrip() {
        let generator_bytes: Vec<u8> = hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap();
        let p = from_bytes_g1affine(&generator_bytes.clone().try_into().unwrap()).unwrap();
        assert_eq!(to_bytes_g1affine(&p).unwrap().as_slice(), &generator_bytes);
    }

    fn get_k_commitment(k: &Fr) -> Result<G1PointBytes, SerializationError> {
        let G = G1Affine::generator();
        to_bytes_g1affine(&G1Affine::from(G.mul(*k)))
    }

    fn generate_shuffle_trackers<T: RngCore>(
        rng: &mut T,
    ) -> Result<Vec<WhiskTracker>, SerializationError> {
        (0..ELL).map(|_| WhiskTracker::from_rand(rng)).collect()
    }

    #[test]
    fn whisk_tracker_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let k = Fr::rand(&mut rng);
        let tracker = WhiskTracker::from_k(&mut rng, &k).unwrap();
        let k_commitment = get_k_commitment(&k).unwrap();

        let tracker_proof = generate_whisk_tracker_proof(&mut rng, &tracker, &k).unwrap();
        assert!(is_valid_whisk_tracker_proof(&tracker, &k_commitment, &tracker_proof).unwrap());

        // Assert correct TRACKER_PROOF_SIZE
        let mut out_data = vec![];
        let mut out = Cursor::new(&mut out_data);
        deserialize_tracker_proof(&tracker_proof)
            .unwrap()
            .serialize_compressed(&mut out)
            .unwrap();
        assert_eq!(out_data.len(), TRACKER_PROOF_SIZE);

        assert_eq!(&hex::encode(tracker_proof), "a994a4f67adaaa5f595809c1eb09e329d9217030e204203009acb39768f29d8ee7ea9cac577426e60a4b6092b06434ed953d27f60af561dce34f18f0111a41ea4188c9aac0249d29a68ce6168a3b31cf830b30f3abf2f7b2e11886c1f5e653a50a91ba585ffeff9902ebba92da6dfe41df7c453b6b71a8557d2da93645996a1e");
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
        let crs = CurdleproofsCrs::generate_crs(ELL);

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
        WhiskShuffleProof::deserialize(Cursor::new(&whisk_shuffle_proof_bytes), crs.log2_n())
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

        assert_eq!(hex::encode(&whisk_shuffle_proof_bytes), "9199d00506683a68fd5bc16b7d12626c4e1d6f64211fe9e356efef27066b1c11b2757c1f23e25c56b788ffa8823eb5488b5ec87a1f99aad91b13e7b4f2a390c43cf33281a910ce6d96413b651bbfbebe6b8c4cd460601b802aaebf6e77c41171b09132c8b747a931aabce8d6d6ff3b8bd9f927945fe751075f8fcb39e2ef6769aee9b57573d6e93a1d8a9e494368e819959561c6e5c8cf905b1317a29259443fc676b480ca27a126637b38824e2a8f8d9fe677bdd280c2595cdfd5a5ffcb01cba9008b3168d78711a7cab788e6f1bd1ba311aa814042e7bdc14e706a44ae5c7988b0649efd4d2666ed10da634670039c862bee475ea33435e2f6481ac0802d8ec480655d0ed25e895609a5683a7c43e990edc9ead9cf32ef3e53c0b00c09399684b10dabc835c51d7f3c747be22bc58f0f11e33b5c137e19759d656574490ec5c9bd96c1bf22a2b69ff727d66d35649aab0fbcd50978206030086a8047d28e4ec3debcc25c545865d0e464048c45a21739a03ede500941fa6ea9fa1aaaa5ed61a62e53f40880581ee3a45e4d05490dcf719dccce1a4224a732bebe95a42ec1e3d93cdfa007b471ba8e95d6ba09cee022951198d934d7638e91a7b156ea2c0d809bc3cfd99e644a37d7000f4e95d5a192563dda00baee0c8bc809c852347301af40dd12e1c7f067a6c007712562053f72b6394d3ce08f1e6b30498fdb7e6c763baf8089f2e5b81ff3a1f7c82ca9f4cb712b74b763db56e61fda94fd91ca57b346b90f007b045655b284a76a628bf649aa956090c0d2625c1278df3f7ff7e1201aee34865ac142bca5e2c0f1355de34d17fd3bc539d89271ba410f17442cb839cda1b83c284f1427535fff7b44a12e2e5aa61e92d7d78da191088858ca908fef252a63578682eb22d746359d57213d1ce6b439905ccbfbfe16071ca38f94ee3908db842e761e3f07c9f169eba725d3be758c774538aaa9ec54dc0f58467fffca60a2af14ffb39a42f2705e4df40ff5d10b68c84caa373d68bd1be52f9d59f127923f9ca0d2fc2a165424163d1724fa475eb68d9bb56fccb361330f5c6434dacc851d71b961a68355cc59a5d904d37fd69e563b1a5615bf9079c6a827f8b84b8aa19130c4932d78e9f5728238140c2bfbe15cab2c4b60e6f4fb3b0f796fa1e73b7fbf90b931e92eb28b320c64c3ba6a028d802db6f144adc8370c3627e548032be09f15e580faeaabb1a2bc53396bd58bc136075bc03a9ea84128bd7b88956f1f79b90ffa920d79cb9e4a6766bd685dc1cf74b3b515b3dc42af5fc09d9e78bbd65cc2e7b06bf70014e40676866d5eeb04dab2c477cbe892689fbc53d854421f7b969c9e6de598e6b927ee77996608732313d7819e266f86c51d6c18422a6e2625dc93ca68a809dbc605b213d80fc56f73a019ccec7666d82348e31107bb48391c9a50b00e3943aaa83fe9425e939e0d22fea249a0f896bd52378bf5287902c099f0df09e1919acc2bb6b4aefeae1400ca0523233a2d8168632aa490798a19683cbb80016af7e935f08ec6d057e913e6e12a281e818c7bdd9132da1409f04b5b2315521589fb09f44e703ede77d12fac795d910a96eea2bfdca106c57c48918a175995a15f2874679ec616b258b8569c9c2f18ae432e4ea3f799fdec6d0c48b1dcf3b202eda293a2167a87ca84c6e431f3697f033ee98af99aa1e728cf48196c4e517309c1516a8d7a6adceb5bddb6649faaa79b949406ab2565d246c839fdb55bcb1f0423abed05fae2951aa4d505f3c79f39b1b9ef1255e25318b504e1f8f288c9aab2f600b531073142abb4f7f2df8b756c625c7b415f5275a4bc25d4d90904dc70ada1bb94665a86f4e73232f4a97d0c8ea840f3ee1bd85ef3b1d5f9591c8a84adf08e839b098d9b6a33a64b4ba8f02e49815cabed6d0f086c1c1d8cb3803c8b8adb8d316c1a0eff29670e948bad171c313fd792def950ef67fcf7259fe248b785db1aa5deaae5496f8cc43bbc64e352af4623e71be9f32d65860e91ec658e9cf63618b45fef34804ef16a1b05a05faed86d789d786756ecefa3f9792a1d14db921851f1dad0014a1af747127e4a42597abfe943afe295192dc64a732a3bac539a7deef3ae1596ec5664e6a668726419b9bb53f9e20c4857e20e1c312c2e0701f8b7fbb1603a98e091bdaea4c2599f6f18f739584b084c5ffd5fefcdb0ae51448addd6ba0dc9c7eaf5efa7cc1bf87fa39ecd45486ade381bb650d8065490f4ee909b5b3e7935620fc541ff58a9793b498f25ea8d4477c6a2def7a53f7cc0684e582ac207cc8b5bd2aa4ee451a70fbaa348dc99dcf6664bbf4ee609626d62289a97fbcce4e17001486ddf4ad26fd9ce42c7217eecd9c51626bace0f122d174a671b80efe9a771e6f33c161853ba47b3eab8264496d387ceeceafb7e039b833435cd94541c9017d16a067e27f75e9fe2fc68376230db732be883ead59171fffe99ad54402ac0060f88b03addfe03ee9b33ef9536728651cf70e8e3cafebf6d28f5f1b6ecdc30c5fd0c9f6f13c09571a1aa8e4e52a7714518ef24df72be8a8806808547718f9ebf7a9adb82f7ee34e2d22c67c6157fbe000a92d771e15c9972e91eb8dfd1c667e381262b12319b70a408e7dcf4514ad1ec06e19140a48413d3c2c6a628e228c1cc196484fbfc006759937882e816cfd1c27f3b8ec18d906549b1c97ee19b9fc23b92cb85ace52828fe741bafe362fe63d8070c63bed043afccdc520084965363bfcba6d3e678c6143bf7ade41db6dbdc4963475d7ea60f7764cc56608c954a707ebe4ff2fc49ab6116fa0b34c02046f76977bceeb7bba85af19547b0992cf93b71304de97db1b6ea725ba3eb8aa7606ac41ec435a291a81a467eac000017ce92300a6ba08155d3b937e7e5af55674c60ff2ab6232e072ddaad37ea09188170c73e047523d0fe499a61f132eb36e8c76deb9cfdb7be1e4fac2b46bd85838df0baa72906dca8b4ab4a76332968aaa5d49aa37e734c3016c54718cc58a2a49b5eac59df28cd1d600f558de8c7a3ff82c4cbfd9ffb1af21cdb09dcc1463d8e0141ee0b983e369f3e8f47588105e7ffd006045a77918be6e7951b31e86f3e3ad343842f6c7b125161fb1de4c6b1f449a715f07f1462483c939148a98f43ab1c133094c03aa68ee1d9fceb01a2e692c20592f72647b580657885f7d7042b3ab623de6dfef1aaa01c9eec1a5d035b5f667126a0840729d4babcdf398b354cac66e208d91c631e4ea6e6ec61cd50fc1c1a6da7abd1ac426e53b71ba5e0a45c2de9fe42368930735a9053fb66ef325eae926bdabec3c5314a313ef6e7812f6050f3f6fcdb2890925cb9d6bed7fb3437788d4e2f8e7d3b6ed581310269bb89838460e413cbc8e63dc5c8d60b67f2aa8acdd5b17c84ffdc495c6f67e8d5e5ba07b2a5c9f2c3c5460273cc5c88fb31c4dcaddf7ee5cc86c30d72ad1d3194f8eab1c68d72e4f70b8c47310fc84683874dff52bac928cc47fbd4b40365c0221d00f98a00fd68a3e0f2bfe887b5e81485aa9a312d8751ad0e99c4a885b4643e3fc85d1f95ec19f39bfd51cf833c7cafa7d35a8bcdfc6d68a73fe6deaf33e6f7aac4e75f836aefe39cb7aafcd7070379bc4fb450c1121b3318fe886125a12ec55d911eaf832778d89b7d59ed08b765b6a413e1c3fc119e034e16d2f77700d52aaaa70a741760a761e79b84e795cbaa83c444c6a4ecfca3b1d812c04e9a50c2f2a107ce745ddd81d0b80de6993e262ead452683d9728b12d2809afa3e3915bac721aa7380baa2a8fa43ab7e7075c37b1f26912fea5cadcde212948f410dc6baa35c4b29addeb31630ef140cff10ff8c89cfc31fb5c2bdb654e94e8a841f489f5ce83f4db07801cde10d53d44821728ca4efb6443817216a940962a1c4e63065ca814ea4a530b3ab540db61f2cf22c9a32c2d03424c91658d8080ca2ef6b7d8e1927f79811b0e7508067c0d1c5cabae8cb22d7258b4dcf36dc947d1e4547ba8a8d7742e06f6f7f0614b530a1496530297394fea04dd58276e67982bf205a84bb95bc1d0e8e8140f6132c93213ca9cdce1ac3c562b986d263cac10b2e804ee938bc739882ce6a22def35160b7f37b6c375c43c2e1b8986b897bfdebbf453a1f01f7dee9ed9881a58c194ae4ed3d52a1052e9516769471023fe7fd6a58e38d979bc2c8d1cba843252d00d039a5628efb461fdc0dddebba94b2c3db7e350f27f8e33451de4d6677ede5bef48260629c2f0c41a21c259606a133c2415767871e7a9b0b44e2637bfa5236dedd8b11d0b3c304484f7de50cd4df4bd9d9c7a10cbaa1d31de9cba7a5dbdeb242c7631a0cbe934d5af04bf558e641aeb14b7a42cbb0d87d462405a35c5367ca0f8318aa11e8940c257df16893a5d086e2e1725eae57cf8aeb78737d01efcdbf697ff72d8385fb3d3e48f2a0ed0ecce04fe50b414c2ffc4ddf5c46baa61844d26dfe395f136b4d9942c9806d612c1cdfb987c082e2dffe0d55d077babdc8131cfb1d4939d454e7710da0e45e8b3231799993ed34fee7280ddcd92ea78aa8debe0cd95ab99d915ad6229db22167f548247d1b469fbc99e1e9e31dce5aac65aa8455822fece8e886f486b2cb246097fec8668e496dd5b23374d1d7be1451118c350828de08a35883cca1f0a6bcb9627e567ddca9a56ba8a01311148105694c1349b2900ebc5c69d8fa6b9d610cb534992873dcd84c8ae51b9b4e4b242e930d1661eef0f7642da2e0c581ad38e9b914adfe7eafc2588033cef22cbf3711a5eb84c25d5d473c2264421418b8c395b899b8964a51c7af3a76607098ecd09603515ff3a131cabc327a89c0f50d0ebf699b6562d39d30fb082ce792f92366c799d781f9ee0c92cb88ac9ac1254e9da2995908e983d25b91be425f35469bf2b3cbf1351a08274225a4b635d4a1c8c70195f3b1d5584e30227e6a2e82660787a6c259690d9e155c2ccbf57704b6206641ef31d103e427dadbf220beed243e6a3bb5e9dc3e131ab92c3475c2941e350fcce1bfa17b78bf95799c822ac3d046f3aad6f007af20b7b1f942cb87f07e61261bb4e3119407d47f9f2e6af4f89a7571059c8ace1d7f0437eabd4931b4c41a1dea8e7c9378eb907a10400ad4074284fb11b5bac39c1b50d101405071cbb29a6cde9714097a42c53c576eec947b3fe5582a498a650c55d16f06cb09e1f1633405818ae70657231b993ffc27e95136881dbf6b278ac005da9180c134da55b11cdadc9e26d1bc2eb953fa1f9dfaf3c006eedeaaf5ef1dcf29c88739650e530c33009272a3e6f97e454bbe47de7c38a521b3bbbc9229e2c07d2e00429d6f9f86efe1fd8d5bbf765acb8c5b166cd0d90ab102adf58eab17b0a8202dab979aa2992c87d20f2fe91710c2fa620766019cd27812b5a00b1c16b2b74096849752e4b7f976f6225fc6a09a4f750ad8ecdbb18eee25af89630f52721edada480d37ab6e89d8a0b0755edc1d7c23a655585551509ea79290f4e27d9312bc27aae99648157615cef08ec7dfe4ea686aa32fcc45cdf004fcabe82ea9a0c4ffcac970450412a5f29455a2d3ecc1b0406c1ec9799c80f4edf97b6716a81137b30949e882b4d8067584b5658624730bbc71121551c686ddf8d9763ad35ef09e70a5afb7081b73b945fcc9edebd18b6ecbb7582da0d6d9a2afddb8ea7b00207f3fa53ad1d8fe3934a937c0cd61a0cd39481f6d7d8d4ea8252b6b833cff0feaeb6977b0db63f10e214e4f837b85046b77458fdda7268224615930967ef945d1b9f220451d8938e5aab8623f2caa66f8fa64075719beb934f0ada487cfb2c2b4a4f44dbc555f804979e7882ab38989308b54c43c1f89b84f8482e7c77f90f420e7a5b1be12dd9f72ee436393e53328dbadf097eabddb878193f686336761c1d53da5dafbec12a0dc6360f467489d984e6a01ecdbbc083e719e078ab33d0ba087c0c0ce6cc87891f01ee8d2bbdace63c9adf29ec4576adf57c5e60f7a1da3ec8cd842bb716561667e455c1baf63ca058e60a55e302deed28ac4fb880c1eb3ef3dc1a546f14efccba0796b5320cd5dca01a677f8362481baa77255118dcf9b227939fb31fe718a0b94683d2bed440719df315c7254e3ccce518bba1c70040c4d0b6e3b9e4b418632579709e48bf6ed16fc7b8b02bd453c7b2a78659aaade9be3094a417f8135be3ba0ac5c63c65dbedffd1575f8496cc861e27936e2ad5fa5aff13e76bec5259850139e81386594043bbc2adc15aa5c79a7fa7c605ee31aec21124fe4907f5afe23f90dc2e55f2f3b5aeb038fcb6b1014bc71968c68de207d391c3fa2f4d080c668cad4bc38");
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
        let G = to_bytes_g1affine(&G1Affine::generator()).unwrap();
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

        let is_first_proposal =
            state.proposer_tracker.r_G == to_bytes_g1affine(&G1Affine::generator()).unwrap();

        let (whisk_registration_proof, whisk_tracker, whisk_k_commitment) = if is_first_proposal {
            // First proposal, validator creates tracker for registering
            let whisk_tracker = WhiskTracker::from_k(&mut rng, &proposer_k).unwrap();
            let whisk_k_commitment = get_k_commitment(&proposer_k).unwrap();
            let whisk_registration_proof =
                generate_whisk_tracker_proof(&mut rng, &whisk_tracker, &proposer_k).unwrap();
            (whisk_registration_proof, whisk_tracker, whisk_k_commitment)
        } else {
            // And subsequent proposals leave registration fields empty
            let whisk_registration_proof = [0; TRACKER_PROOF_SIZE];
            let whisk_tracker = WhiskTracker::from_k_r(&Fr::one(), &Fr::one()).unwrap();
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
        let crs = CurdleproofsCrs::generate_crs(ELL);

        // Initial tracker in state
        let shuffled_trackers = generate_shuffle_trackers(&mut rng).unwrap();

        let proposer_index = 15400;
        let proposer_initial_k = compute_initial_k(proposer_index);

        // Initial dummy values, r = 1
        let mut state = State {
            proposer_tracker: WhiskTracker::from_k_r(&proposer_initial_k, &Fr::one()).unwrap(),
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

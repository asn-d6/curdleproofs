use ark_bls12_381::G1Affine;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger384, Fp384};
use ark_serialize::SerializationError;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use curdleproofs::{
    crs::{CurdleproofsCrs, CurdleproofsCrsHex, CRS_EXTRA_POINTS},
    whisk::{generate_whisk_shuffle_proof, is_valid_whisk_shuffle_proof, WhiskTracker},
    N_BLINDERS,
};
use sha2::{Digest, Sha256};

fn generate_random_points(num_points: usize, seed: &str) -> (Vec<G1Affine>, u64) {
    let mut points = vec![];
    let mut increment = 0u64;

    while points.len() != num_points {
        let mut digest = Sha256::new();
        digest.update(seed.as_bytes());

        let mut b = [0u8; 8];
        b[..].copy_from_slice(&increment.to_be_bytes());
        digest.update(&b);

        let hash = digest.finalize();

        // Convert &[u8] of 32 bytes, into [u64; 6] with right zero padding
        let mut x = [0u64; 6];
        for i in 0..4 {
            x[i] = u64::from_be_bytes(hash[8 * i..8 * (i + 1)].try_into().unwrap());
        }

        if let Some(p) =
            G1Affine::get_point_from_x_unchecked(Fp384::new(BigInteger384::new(x)), false)
        {
            let z = p.mul_by_cofactor();
            if z.is_in_correct_subgroup_assuming_on_curve() {
                points.push(z);
                println!(
                    "point {}/{} found, {} attempts",
                    points.len(),
                    num_points,
                    increment
                );
            }
        }

        increment += 1;
    }

    (points, increment)
}

#[test]
fn ethereum_crs_128_seed() {
    let n = 128;
    let (points, increment) =
        generate_random_points(n + CRS_EXTRA_POINTS, "nankokita_no_kakurenbo");
    let crs = CurdleproofsCrs::from_points(n, &points).unwrap();

    println!("generated random CRS, n_attempts {}", increment);

    // Check CRS works
    test_crs(&crs, n);

    let out =
        serde_json::to_string_pretty::<CurdleproofsCrsHex>(&(&crs).try_into().unwrap()).unwrap();
    println!("{}", out);
}

#[test]
fn ethereum_crs_8_seed() {
    let n = 8;
    let (points, increment) =
        generate_random_points(n + CRS_EXTRA_POINTS, "nankokita_no_kakurenbo");
    let crs = CurdleproofsCrs::from_points(n, &points).unwrap();

    println!("generated random CRS, n_attempts {}", increment);

    // TODO: Support variable N
    // Check CRS works
    // test_crs(&crs, n);

    let out =
        serde_json::to_string_pretty::<CurdleproofsCrsHex>(&(&crs).try_into().unwrap()).unwrap();
    println!("{}", out);
}

#[test]
fn ethereum_crs_128_unsafe_rand() {
    let n = 128;
    let crs = CurdleproofsCrs::generate_crs(n).unwrap(); // Note that +CRS_EXTRA_POINTS is done inside.

    // Check CRS works
    test_crs(&crs, n);
}

fn test_crs(crs: &CurdleproofsCrs, n: usize) {
    let mut rng = StdRng::seed_from_u64(0);
    let trackers = generate_shuffle_trackers(&mut rng, n).unwrap();

    let (whisk_post_shuffle_trackers, whisk_shuffle_proof_bytes) =
        generate_whisk_shuffle_proof(&mut rng, &crs, &trackers).unwrap();
    assert!(is_valid_whisk_shuffle_proof(
        &mut rng,
        &crs,
        &trackers,
        &whisk_post_shuffle_trackers,
        &whisk_shuffle_proof_bytes
    )
    .unwrap());
}

fn generate_shuffle_trackers<T: RngCore>(
    rng: &mut T,
    n: usize,
) -> Result<Vec<WhiskTracker>, SerializationError> {
    (0..n - N_BLINDERS)
        .map(|_| WhiskTracker::from_rand(rng))
        .collect()
}

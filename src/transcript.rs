//! A Fiat-Shamir transcript implementation using Merlin
//!
//! This module provides a bunch of helper methods to tailor the transcript's ergonomics to our use case
use core::iter;

use merlin::Transcript;

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;

/// A Transcript with some methods for feeding it and for obtaining challenges as field elements
pub trait CurdleproofsTranscript {
    /// Append an `item` to the transcript
    fn append(&mut self, label: &'static [u8], item: &impl CanonicalSerialize);

    /// Append a list of `items` to the transcript
    fn append_list<T: CanonicalSerialize>(&mut self, label: &'static [u8], items: &[&T]);

    /// Get a challenge out of the transcript
    fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Fr;

    /// Get a list of `n` challenges out of the transcript
    fn get_and_append_challenges(&mut self, label: &'static [u8], n: usize) -> Vec<Fr>;
}

impl CurdleproofsTranscript for Transcript {
    fn append(&mut self, label: &'static [u8], item: &impl CanonicalSerialize) {
        let mut bytes = Vec::new();
        item.serialize(&mut bytes).unwrap();
        self.append_message(label, &bytes)
    }

    fn append_list<T: CanonicalSerialize>(&mut self, label: &'static [u8], items: &[&T]) {
        for item in items {
            self.append(label, *item);
        }
    }

    fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Fr {
        loop {
            let mut buf = [0; 64];
            self.challenge_bytes(label, &mut buf);
            if let Some(e) = Fr::from_random_bytes(&buf) {
                if e != Fr::zero() {
                    // Feed the fresh challenge back into the transcript
                    self.append(label, &e);

                    return e;
                }
            }
        }
    }

    fn get_and_append_challenges(&mut self, label: &'static [u8], n: usize) -> Vec<Fr> {
        iter::repeat_with(|| self.get_and_append_challenge(label))
            .take(n)
            .collect()
    }
}

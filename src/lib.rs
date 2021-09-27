#![doc = include_str!("../README.md")]

pub mod commitments;
#[doc = include_str!("../doc/curdleproofs.md")]
pub mod curdleproofs;
mod errors;
#[doc = include_str!("../doc/grand-product-argument.md")]
pub mod grand_product_argument;
#[doc = include_str!("../doc/inner-product-argument.md")]
pub mod inner_product_argument;
pub mod msm_accumulator;
#[doc = include_str!("../doc/same-msm-argument.md")]
pub mod same_multiscalar_argument;
#[doc = include_str!("../doc/same-permutation-argument.md")]
pub mod same_permutation_argument;
#[doc = include_str!("../doc/same-scalar-argument.md")]
pub mod same_scalar_argument;
pub mod transcript;
pub mod util;

#[doc = include_str!("../doc/notes.md")]
pub mod notes {
    #[doc = include_str!("../doc/optimizations.md")]
    pub mod optimizations {}
    #[doc = include_str!("../doc/todo.md")]
    pub mod todo {}
}

/// Number of blinders $n_{bl}$ needed for zero-knowledge
pub const N_BLINDERS: usize = 4;

#![allow(dead_code, non_snake_case)]

mod error;
pub mod utils;
#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;
#[cfg(feature = "test")]
pub mod tests;

pub use crate::error::Error;

pub type Result<T> = std::result::Result<T, Error>;

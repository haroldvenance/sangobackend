//! `sango-codec` — encodage binaire canonique du protocole Sango V1.
//!
//! Ce crate définit :
//!
//! - les traits [`Encode`] et [`Decode`] ;
//! - [`Encoder`] / [`Decoder`] bas niveau ;
//! - les implémentations pour les types de [`sango_primitives`] ;
//! - les règles canoniques (little-endian, longueurs préfixées, unicité).
//!
//! ## Règles canoniques (Freeze, section 10)
//!
//! - Les entiers sont encodés en **little-endian**.
//! - Un `Vec<u8>` est encodé `u32 length || bytes`.
//! - Un `Vec<T>` est encodé `u32 count || elements`.
//! - Un tableau fixe `[u8; N]` est encodé **sans** préfixe.
//! - Aucun JSON, aucun RLP, aucun layout mémoire Rust.
//! - `decode(encode(x)) == x`.
//!
//! ## Non-canonique
//!
//! Le décodeur rejette :
//!
//! - les entrées tronquées ;
//! - les bytes résiduels après décodage (`decode_exact`) ;
//! - une longueur déclarée plus grande que l'entrée restante.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod decoder;
mod encoder;
mod error;
mod impls;
mod traits;

pub use decoder::Decoder;
pub use encoder::Encoder;
pub use error::CodecError;
pub use traits::{Decode, Encode};

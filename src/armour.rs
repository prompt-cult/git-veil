//! PGP armour markers.
//!
//! Every literal below is wire format: the exact armour boundary string
//! used when parsing or emitting an OpenPGP armoured block. They are
//! defined here, once, so that no call site hand-copies a marker that
//! could silently drift from the real armour format.

pub const SIG_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
pub const SIG_END: &str = "-----END PGP SIGNATURE-----";
pub const PUBLIC_KEY_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
pub const PUBLIC_KEY_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
pub const PRIVATE_KEY_BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
pub const PRIVATE_KEY_END: &str = "-----END PGP PRIVATE KEY BLOCK-----";

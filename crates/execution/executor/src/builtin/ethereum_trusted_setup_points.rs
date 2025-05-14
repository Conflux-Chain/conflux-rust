// Based on source code from the revm project (https://github.com/bluealloy/revm) under the MIT License.

use c_kzg::KzgSettings;
use derive_more::{AsMut, AsRef, Deref, DerefMut};
use once_cell::race::OnceBox;

pub use c_kzg::{BYTES_PER_G1_POINT, BYTES_PER_G2_POINT};

/// Number of G1 Points.
pub const NUM_G1_POINTS: usize = 4096;

/// Number of G2 Points.
pub const NUM_G2_POINTS: usize = 65;

/// A newtype over list of G1 point from kzg trusted setup.
#[derive(Debug, Clone, PartialEq, AsRef, AsMut, Deref, DerefMut)]
#[repr(transparent)]
pub struct G1Points(pub [[u8; BYTES_PER_G1_POINT]; NUM_G1_POINTS]);

impl Default for G1Points {
    fn default() -> Self { Self([[0; BYTES_PER_G1_POINT]; NUM_G1_POINTS]) }
}

/// A newtype over list of G2 point from kzg trusted setup.
#[derive(Debug, Clone, Eq, PartialEq, AsRef, AsMut, Deref, DerefMut)]
#[repr(transparent)]
pub struct G2Points(pub [[u8; BYTES_PER_G2_POINT]; NUM_G2_POINTS]);

impl Default for G2Points {
    fn default() -> Self { Self([[0; BYTES_PER_G2_POINT]; NUM_G2_POINTS]) }
}

/// Default G1 points.
pub const G1_POINTS: &G1Points = {
    const BYTES: &[u8] = include_bytes!("./g1_points.bin");
    assert!(BYTES.len() == core::mem::size_of::<G1Points>());
    unsafe { &*BYTES.as_ptr().cast::<G1Points>() }
};

/// Default G2 points.
pub const G2_POINTS: &G2Points = {
    const BYTES: &[u8] = include_bytes!("./g2_points.bin");
    assert!(BYTES.len() == core::mem::size_of::<G2Points>());
    unsafe { &*BYTES.as_ptr().cast::<G2Points>() }
};

static DEFAULT: OnceBox<KzgSettings> = OnceBox::new();

pub fn default_kzg_settings() -> &'static KzgSettings {
    DEFAULT.get_or_init(|| {
        let settings = KzgSettings::load_trusted_setup(
            G1_POINTS.as_ref(),
            G2_POINTS.as_ref(),
        )
        .expect("failed to load default trusted setup");
        Box::new(settings)
    })
}

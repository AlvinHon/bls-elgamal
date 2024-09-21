/// A ciphertext is a pair of two points.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext<P>(pub P, pub P); // (rG, m + rY)

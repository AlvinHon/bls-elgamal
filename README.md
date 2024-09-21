# Elgamal Encryption

This crate provides an implementation of the Elgamal encryption scheme over elliptic curves using the BLS12-381 curve (G1).

## Example

```rust
use ark_std::UniformRand;
use bls_elgamal::{Fr, SecretKey, G1};
use rand::prelude::StdRng;
use rand_core::SeedableRng;
    
fn main() {
    let mut rng = StdRng::from_entropy();
    let x = Fr::rand(&mut rng);
    let g1: G1 = G1::rand(&mut rng);
    
    // Create a secret key and a public key
    let sk = SecretKey::new(g1, x);
    let pk = sk.public_key();

    // Define a message and randomness
    let m = G1::rand(&mut rng);
    let r = Fr::rand(&mut rng);

    // Encrypt and decrypt the message
    let ciphertext = pk.encrypt(m, r);
    let decrypted_m = sk.decrypt(ciphertext);

    assert_eq!(m, decrypted_m);
}
```
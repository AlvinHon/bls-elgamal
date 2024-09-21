use ark_std::UniformRand;
use bls_elgamal::{Ciphertext, Fr, SecretKey, G1};
use rand::prelude::StdRng;
use rand_core::SeedableRng;

#[test]
fn test_encrypt_decrypt() {
    for _ in 0..100 {
        let mut rng = StdRng::from_entropy();
        let x = Fr::rand(&mut rng);
        let g1: G1 = G1::rand(&mut rng);

        let sk = SecretKey::new(g1, x);
        let pk = sk.public_key();

        let m = G1::rand(&mut rng);
        let r = Fr::rand(&mut rng);

        // encrypt and decrypt the message
        let ct = pk.encrypt(m, r);
        let decrypted_m = sk.decrypt(ct);
        assert_eq!(m, decrypted_m);
    }
}

#[test]
fn test_encrypt_different_message() {
    for _ in 0..100 {
        let mut rng = StdRng::from_entropy();
        let x = Fr::rand(&mut rng);
        let g1: G1 = G1::rand(&mut rng);

        let sk = SecretKey::new(g1, x);
        let pk = sk.public_key();

        let m1 = G1::rand(&mut rng);
        let m2 = G1::rand(&mut rng);
        let r = Fr::rand(&mut rng);

        // encrypt two different messages
        let ct1 = pk.encrypt(m1, r);
        let ct2 = pk.encrypt(m2, r);

        assert_ne!(ct1, ct2);
    }
}

#[test]
fn test_decrypt_modified_ciphertext() {
    for _ in 0..100 {
        let mut rng = StdRng::from_entropy();
        let x = Fr::rand(&mut rng);
        let g1: G1 = G1::rand(&mut rng);

        let sk = SecretKey::new(g1, x);
        let pk = sk.public_key();

        let m = G1::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let Ciphertext(c1, c2) = pk.encrypt(m, r);

        // modify the ciphertext
        let m_c1 = c1 + G1::rand(&mut rng);
        let m_c2 = c2 + G1::rand(&mut rng);
        let modified_ct = Ciphertext(m_c1, m_c2);

        let decrypted_m = sk.decrypt(modified_ct);
        assert_ne!(m, decrypted_m);
    }
}

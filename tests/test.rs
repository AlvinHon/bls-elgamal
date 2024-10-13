use ark_ec::CurveGroup;
use ark_std::UniformRand;
use bls_elgamal::{Ciphertext, Fr, G1Affine, PublicKey, SecretKey, G1};
use rand::prelude::StdRng;
use rand_core::SeedableRng;

#[test]
fn test_encrypt_decrypt() {
    for _ in 0..100 {
        let mut rng = StdRng::from_entropy();
        let x = Fr::rand(&mut rng);
        let g1 = G1Affine::rand(&mut rng);

        let sk = SecretKey::new(g1, x);
        let pk = sk.public_key();

        let m = G1Affine::rand(&mut rng);
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
        let g1 = G1Affine::rand(&mut rng);

        let sk = SecretKey::new(g1, x);
        let pk = sk.public_key();

        let m1 = G1Affine::rand(&mut rng);
        let m2 = G1Affine::rand(&mut rng);
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
        let g1 = G1Affine::rand(&mut rng);

        let sk = SecretKey::new(g1, x);
        let pk = sk.public_key();

        let m = G1Affine::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let Ciphertext(c1, c2) = pk.encrypt(m, r);

        // modify the ciphertext
        let m_c1 = c1 + G1Affine::rand(&mut rng);
        let m_c2 = c2 + G1Affine::rand(&mut rng);
        let modified_ct = Ciphertext(m_c1.into_affine(), m_c2.into_affine());

        let decrypted_m = sk.decrypt(modified_ct);
        assert_ne!(m, decrypted_m);
    }
}

#[test]
fn test_homomorphic_ciphertext() {
    for _ in 0..100 {
        let mut rng = StdRng::from_entropy();
        let x = Fr::rand(&mut rng);
        let g1 = G1Affine::rand(&mut rng);

        let sk = SecretKey::new(g1, x);
        let pk = sk.public_key();

        let m1 = G1Affine::rand(&mut rng);
        let m2 = G1Affine::rand(&mut rng);
        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);

        // encrypt two messages
        let ct1 = pk.encrypt(m1, r1);
        let ct2 = pk.encrypt(m2, r2);

        // add two ciphertexts
        let ct3 = &ct1 + &ct2;
        let decrypted_m1 = sk.decrypt(ct3);
        let decrypted_m2 = m1 + m2;
        assert_eq!(decrypted_m1, decrypted_m2);
    }
}

#[test]
fn test_serde() {
    let mut rng = StdRng::from_entropy();
    let x = Fr::rand(&mut rng);
    let g1 = G1Affine::rand(&mut rng);

    let sk = SecretKey::new(g1, x);
    let pk = sk.public_key();

    let m = G1Affine::rand(&mut rng);
    let r = Fr::rand(&mut rng);
    let ct = pk.encrypt(m, r);

    // test serialize and deserialize for secret key
    let serialized = bincode::serialize(&sk).unwrap();
    let deserialized_sk: SecretKey = bincode::deserialize(&serialized).unwrap();
    assert!(sk == deserialized_sk);

    // test serialize and deserialize for public key
    let serialized = bincode::serialize(&pk).unwrap();
    let deserialized_pk: PublicKey = bincode::deserialize(&serialized).unwrap();
    assert!(pk == deserialized_pk);

    // test serialize and deserialize for ciphertext
    let serialized = bincode::serialize(&ct).unwrap();
    let deserialized_ct: Ciphertext<G1> = bincode::deserialize(&serialized).unwrap();
    assert_eq!(ct, deserialized_ct);

    // test encrypt and decrypt after serialization and deserialization
    let check_ct = deserialized_pk.encrypt(m, r);
    assert_eq!(ct, check_ct);
    let decrypt_m = deserialized_sk.decrypt(check_ct);
    assert_eq!(m, decrypt_m);
}

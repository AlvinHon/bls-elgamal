use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup,
};
use ark_std::{rand::Rng, One, UniformRand, Zero};
use ndarray::{arr2, Array2, Axis};
use std::ops::Mul;

/// Common reference string for the GS proof system.
#[derive(Clone, Debug)]
pub(crate) struct Crs<E: Pairing> {
    p1: E::G1,        // generator
    p2: E::G2,        // generator
    u: Array2<E::G1>, // dim = 2 x 2
    v: Array2<E::G2>, // dim = 2 x 2
}

impl<E: Pairing> Crs<E> {
    pub(crate) fn rand<R: Rng>(rng: &mut R) -> Self {
        let p1 = E::G1::rand(rng);
        let p2 = E::G2::rand(rng);

        let a1 = E::ScalarField::rand(rng);
        let t1 = E::ScalarField::rand(rng);
        let a2 = E::ScalarField::rand(rng);
        let t2 = E::ScalarField::rand(rng);

        let u = arr2(&[[p1, p1.mul(t1)], [p1.mul(a1), p1.mul(a1 * t1)]]);
        let v = arr2(&[[p2, p2.mul(t2)], [p2.mul(a2), p2.mul(a2 * t2)]]);

        Self { p1, p2, u, v }
    }

    fn u1(&self) -> Array2<E::G1> {
        arr2(&[[self.u[(0, 0)], self.u[(1, 0)]]])
    }

    fn u2(&self) -> Array2<E::G1> {
        arr2(&[[self.u[(0, 1)], self.u[(1, 1)]]])
    }

    fn v1(&self) -> Array2<E::G2> {
        arr2(&[[self.v[(0, 0)], self.v[(1, 0)]]])
    }

    fn v2(&self) -> Array2<E::G2> {
        arr2(&[[self.v[(0, 1)], self.v[(1, 1)]]])
    }
}

pub struct Proof<E: Pairing> {
    c: Array2<E::G1>,
    d: Array2<E::G2>,
    pi: Array2<E::G2>,
    theta: Array2<E::G1>,
}

impl<E: Pairing> Proof<E> {
    pub(crate) fn randomize<R: Rng>(
        &self,
        rng: &mut R,
        crs: &Crs<E>,
        a: Vec<E::G1>,
        b: Vec<E::ScalarField>,
    ) -> Self {
        let m = self.c.dim().0;
        let n = self.d.dim().0;

        let r = Array2::from_shape_fn((m, 2), |_| E::ScalarField::rand(rng));
        let s = Array2::from_shape_fn((n, 1), |_| E::ScalarField::rand(rng));

        let new_c = randomize_com_x(&crs, &r, &self.c);
        let new_d = randomize_com_y(&crs, &s, &self.d);

        let t = Array2::from_shape_fn((1, 2), |_| E::ScalarField::rand(rng));

        let a = Array2::from_shape_vec((n, 1), a).unwrap();
        let b = Array2::from_shape_vec((m, 1), b).unwrap();

        let (pi, theta) = randomize_proof(crs, &r, &s, &t, &a, &b, &self.pi, &self.theta);

        Self {
            c: new_c,
            d: new_d,
            pi,
            theta,
        }
    }
}

/// Create a GS proof for the multi-scalar multiplication equation yA + bX = c on G1.
pub(crate) fn prove<E: Pairing, R: Rng>(
    rng: &mut R,
    crs: &Crs<E>,
    a: Vec<E::G1>,
    y: Vec<E::ScalarField>,
    x: Vec<E::G1>,
    b: Vec<E::ScalarField>,
) -> Proof<E> {
    let m = x.len();
    let n = y.len();
    assert!(m == a.len());
    assert!(n == b.len());

    let a = Array2::from_shape_vec((n, 1), a).unwrap();
    let y = Array2::from_shape_vec((n, 1), y).unwrap();
    let x = Array2::from_shape_vec((m, 1), x).unwrap();
    let b = Array2::from_shape_vec((m, 1), b).unwrap();

    let r = Array2::from_shape_fn((m, 2), |_| E::ScalarField::rand(rng));
    let s = Array2::from_shape_fn((n, 1), |_| E::ScalarField::rand(rng));
    let t = Array2::from_shape_fn((1, 2), |_| E::ScalarField::rand(rng));

    let c = commit_x(crs, &r, &x);
    let d = commit_y(crs, &s, &y);

    let (pi, theta) = proof(crs, &r, &s, &t, &a, &b);

    Proof { c, d, pi, theta }
}

/// Verify a GS proof for the multi-scalar multiplication equation yA + bX = c on G1.
pub(crate) fn verify<E: Pairing>(
    crs: &Crs<E>,
    a: Vec<E::G1>,
    b: Vec<E::ScalarField>,
    target: E::G1,
    proof: &Proof<E>,
) -> bool {
    let m = b.len();
    let n = a.len();

    let Proof { c, d, pi, theta } = proof;
    let a = Array2::from_shape_vec((n, 1), a).unwrap();
    let b = Array2::from_shape_vec((m, 1), b).unwrap();

    // l(a) d + c l(b) = l_t(target) + u pi + F(theta, v1)
    let lhs = matmul::<E>(&l1(&a).reversed_axes(), d)
        + matmul::<E>(&c.clone().reversed_axes(), &lz2(crs, &b));
    let rhs = l_t(crs, target)
        + matmul::<E>(&crs.u.clone().reversed_axes(), pi)
        + f::<E>(theta, &crs.v1());

    lhs == rhs
}

/// Commit variable (group element) x in GS Proof.
fn commit_x<E: Pairing>(
    crs: &Crs<E>,
    r: &Array2<E::ScalarField>,
    x: &Array2<E::G1>,
) -> Array2<E::G1> {
    // c = l(x) + Ru
    l1(x) + scalar_matmul_g1::<E>(r, &crs.u)
}

fn randomize_com_x<E: Pairing>(
    crs: &Crs<E>,
    r: &Array2<E::ScalarField>, // m x 2
    c: &Array2<E::G1>,
) -> Array2<E::G1> {
    // c' = c + Ru
    c + scalar_matmul_g1::<E>(&r, &crs.u)
}

/// Commit variable (scalar) y in GS Proof.
fn commit_y<E: Pairing>(
    crs: &Crs<E>,
    s: &Array2<E::ScalarField>,
    y: &Array2<E::ScalarField>,
) -> Array2<E::G2> {
    // d = l(y) + s v1
    lz2(crs, y) + scalar_matmul_g2::<E>(s, &crs.v1())
}

fn randomize_com_y<E: Pairing>(
    crs: &Crs<E>,
    s: &Array2<E::ScalarField>, // n x 1
    d: &Array2<E::G2>,
) -> Array2<E::G2> {
    // d' = d + s v1
    d + scalar_matmul_g2::<E>(&s, &crs.v1())
}

/// Create a GS proof. Returns pi and theta.
fn proof<E: Pairing>(
    crs: &Crs<E>,
    r: &Array2<E::ScalarField>, // m x 2
    s: &Array2<E::ScalarField>, // n x 1
    t: &Array2<E::ScalarField>, // 1 x 2
    a: &Array2<E::G1>,          // n x 1
    b: &Array2<E::ScalarField>, // m x 1
) -> (Array2<E::G2>, Array2<E::G1>) {
    // phi = R^T l(b) - T^T v1
    let phi = scalar_matmul_g2::<E>(&r.clone().reversed_axes(), &lz2(crs, b))
        - scalar_matmul_g2::<E>(&t.clone().reversed_axes(), &crs.v1());

    // theta = s^T l(a) + T u
    let theta = scalar_matmul_g1::<E>(&s.clone().reversed_axes(), &l1(a))
        + scalar_matmul_g1::<E>(t, &crs.u);

    (phi, theta)
}

fn randomize_proof<E: Pairing>(
    crs: &Crs<E>,
    r: &Array2<E::ScalarField>, // m x 2
    s: &Array2<E::ScalarField>, // n x 1
    t: &Array2<E::ScalarField>, // 1 x 2
    a: &Array2<E::G1>,          // n x 1
    b: &Array2<E::ScalarField>, // m x 1
    pi: &Array2<E::G2>,
    theta: &Array2<E::G1>,
) -> (Array2<E::G2>, Array2<E::G1>) {
    // phi' = phi + R^T l(b) - T^T v1
    let phi = pi.clone() + scalar_matmul_g2::<E>(&r.clone().reversed_axes(), &lz2(crs, b))
        - scalar_matmul_g2::<E>(&t.clone().reversed_axes(), &crs.v1());

    // theta' = theta + s^T l(a) + T u
    let theta = theta.clone()
        + scalar_matmul_g1::<E>(&s.clone().reversed_axes(), &l1(a))
        + scalar_matmul_g1::<E>(t, &crs.u);

    (phi, theta)
}

/// Mapping function of Group elements, l(a) = [0 | a], dim = (m, 2)
fn l1<G: CurveGroup>(a: &Array2<G>) -> Array2<G> {
    let a = a.clone();
    let m = a.dim().0;
    let mut zeros = Array2::from_elem((m, 1), G::zero());
    zeros.append(Axis(1), a.view()).unwrap(); // dim = (m, 2)
    zeros
}

/// Mapping function of Field elements, // l(z) = z u where u = u2 + (0, p). dim = (m, 2)
fn lz1<E: Pairing>(crs: &Crs<E>, z: &Array2<E::ScalarField>) -> Array2<E::G1> {
    let m = z.dim().0;

    // u = u2 + (0, p) = [u[0, 1] | u[1, 1] + p]
    let mut u = Array2::from_elem((m, 1), crs.u[(0, 1)]);
    let ps = Array2::from_elem((m, 1), crs.u[(1, 1)] + crs.p1);
    u.append(Axis(1), ps.view()).unwrap(); // dim = (m, 2)

    // l(z) = z u
    u * z
}

/// Mapping function of Field elements, // l(z) = z v where v = v2 + (0, p). dim = (m, 2)
fn lz2<E: Pairing>(crs: &Crs<E>, z: &Array2<E::ScalarField>) -> Array2<E::G2> {
    let m = z.dim().0;

    // v = v2 + (0, p) = [v[0, 1] | v[1, 1] + p]
    let mut v = Array2::from_elem((m, 1), crs.v[(0, 1)]);
    let ps = Array2::from_elem((m, 1), crs.v[(1, 1)] + crs.p2);
    v.append(Axis(1), ps.view()).unwrap(); // dim = (m, 2)

    // l(z) = z u
    v * z
}

/// Mapping function of target group element G1. Returns matrix with dim = (2, 2)
fn l_t<E: Pairing>(crs: &Crs<E>, target: E::G1) -> Array2<PairingOutput<E>> {
    let x = arr2(&[[E::G1::zero(), target]]);
    let y = lz2(crs, &arr2(&[[E::ScalarField::one()]]));
    f(&x, &y)
}

/// Mapping function of paring product on group elements G1 and G2. Returns matrix with dim = (2, 2)
fn f<E: Pairing>(x: &Array2<E::G1>, y: &Array2<E::G2>) -> Array2<PairingOutput<E>> {
    // ([[x1, x2]], [[y1, y2]]) -> [[e(x1, y1), e(x1, y2)], [e(x2, y1), e(x2, y2)]]

    arr2(&[
        [
            E::pairing(x[(0, 0)], y[(0, 0)]),
            E::pairing(x[(0, 0)], y[(0, 1)]),
        ],
        [
            E::pairing(x[(0, 1)], y[(0, 0)]),
            E::pairing(x[(0, 1)], y[(0, 1)]),
        ],
    ])
}

/// Scalar matrix multiplication, left matrix is scalar and right matrix is group element (G1).
pub(crate) fn scalar_matmul_g1<E: Pairing>(
    a: &Array2<E::ScalarField>,
    b: &Array2<E::G1>,
) -> Array2<E::G1> {
    let (m, n_prime) = a.dim();
    let (m_prime, n) = b.dim();
    assert!(n_prime == m_prime);

    let mut res = Array2::from_elem((m, n), E::G1::zero());
    for i in 0..m {
        for j in 0..n {
            let mut sum = E::G1::zero();
            for k in 0..n_prime {
                sum += b[[k, j]].mul(a[[i, k]]);
            }
            res[[i, j]] = sum;
        }
    }

    res
}

/// Scalar matrix multiplication, left matrix is group element (G1) and right matrix is group element (G2).
fn matmul<E: Pairing>(a: &Array2<E::G1>, b: &Array2<E::G2>) -> Array2<PairingOutput<E>> {
    let (m, n_prime) = a.dim();
    let (m_prime, n) = b.dim();
    assert!(n_prime == m_prime);

    let mut res = Array2::from_elem((m, n), PairingOutput::zero());
    for i in 0..m {
        for j in 0..n {
            let mut sum = PairingOutput::zero();
            for k in 0..n_prime {
                sum += E::pairing(a[[i, k]], b[[k, j]]);
            }
            res[[i, j]] = sum;
        }
    }

    res
}

/// Scalar matrix multiplication, left matrix is scalar and right matrix is group element (G2).
fn scalar_matmul_g2<E: Pairing>(a: &Array2<E::ScalarField>, b: &Array2<E::G2>) -> Array2<E::G2> {
    let (m, n_prime) = a.dim();
    let (m_prime, n) = b.dim();
    assert!(n_prime == m_prime);

    let mut res = Array2::from_elem((m, n), E::G2::zero());
    for i in 0..m {
        for j in 0..n {
            let mut sum = E::G2::zero();
            for k in 0..n_prime {
                sum += b[[k, j]].mul(a[[i, k]]);
            }
            res[[i, j]] = sum;
        }
    }

    res
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Bls12_381 as E;

    use crate::{Fr, G1};

    use super::*;

    #[test]
    fn test_gs_proof() {
        let rng = &mut ark_std::test_rng();

        let crs = Crs::<E>::rand(rng);

        // c = m + rY
        let m = G1::rand(rng);
        let y = G1::rand(rng);
        let r = Fr::rand(rng);
        let c = m + y.mul(r);

        // GS proof for multi-scalar multiplication equation:
        // yA + bX = c
        // where y = [r], A = [Y], X = [m], b = [1]

        let proof = prove(rng, &crs, vec![y], vec![r], vec![m], vec![Fr::one()]);

        assert!(verify(&crs, vec![y], vec![Fr::one()], c, &proof));

        // Test randomization

        let new_proof = proof.randomize(rng, &crs, vec![y], vec![Fr::one()]);
        assert!(proof.c != new_proof.c);
        assert!(proof.d != new_proof.d);
        assert!(proof.pi != new_proof.pi);
        assert!(proof.theta != new_proof.theta);

        assert!(verify(&crs, vec![y], vec![Fr::one()], c, &new_proof));
    }
}

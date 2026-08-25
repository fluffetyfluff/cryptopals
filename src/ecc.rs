use crate::oracles::random_biguint;
use crate::primitives::{bigint, bigint_hex, hex_encode, modexp, modinv, sha_1};
use crypto_bigint::{NonZero, OddUint, U2048};

pub trait GroupElement: Clone {
    fn add(&self, rhs: &Self) -> Self;

    fn identity(&self) -> Self;

    fn inverse(&self) -> Self;

    fn coord(&self) -> Option<U2048>;

    fn mul(&self, pow: &U2048) -> Self {
        let mut ans = self.identity();
        let mut square = self.clone();

        let bits = pow.bits_vartime();
        for i in 0..bits {
            if (pow.shr_vartime(i).as_words()[0] & 1) == 1 {
                ans = ans.add(&square);
            };
            square = square.add(&square);
        }
        ans
    }
}

#[derive(Clone, PartialEq)]
pub struct PrimeGroup {
    p: OddUint<{ U2048::LIMBS }>,
}

#[derive(Clone, PartialEq)]
pub struct PrimeGroupPoint<'a> {
    x: U2048,
    group: &'a PrimeGroup,
}

impl GroupElement for PrimeGroupPoint<'_> {
    fn add(&self, rhs: &Self) -> Self {
        assert!(self.group == rhs.group);
        let x = self.x.mul_mod_vartime(&rhs.x, self.group.p.as_nz_ref());
        Self {
            x,
            group: self.group,
        }
    }

    fn identity(&self) -> Self {
        Self {
            x: U2048::ONE,
            group: self.group,
        }
    }

    fn inverse(&self) -> Self {
        let x = modinv(&self.x, self.group.p.as_nz_ref()).unwrap();
        Self {
            x,
            group: self.group,
        }
    }

    fn coord(&self) -> Option<U2048> {
        Some(self.x)
    }

    fn mul(&self, pow: &U2048) -> Self {
        let x = modexp(&self.x, pow, &self.group.p);
        Self {
            x,
            group: self.group,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct EllipticCurve {
    a: U2048,
    b: U2048,
    p: OddUint<{ U2048::LIMBS }>,
}

impl EllipticCurve {
    pub fn new(a: U2048, b: U2048, p: OddUint<{ U2048::LIMBS }>) -> Self {
        Self { a, b, p }
    }
}

#[derive(Clone, PartialEq)]
pub enum Point {
    O,
    Point { x: U2048, y: U2048 },
}

#[derive(Clone, PartialEq)]
pub struct EllipticCurvePoint<'a> {
    point: Point,
    curve: &'a EllipticCurve,
}

impl<'a> EllipticCurvePoint<'a> {
    pub fn new(point: Point, curve: &'a EllipticCurve) -> Self {
        Self { point, curve }
    }
}

impl GroupElement for EllipticCurvePoint<'_> {
    fn add(&self, rhs: &Self) -> Self {
        assert!(self.curve == rhs.curve);
        let three = bigint(3);
        let two = bigint(2);
        let p_nz = self.curve.p.as_nz_ref();

        if let Point::Point { x, y } = self.point {
            let x1 = x;
            let y1 = y;
            if let Point::Point { x, y } = rhs.point {
                let x2 = x;
                let y2 = y;
                if *self == rhs.inverse() {
                    return Self {
                        point: Point::O,
                        curve: self.curve,
                    };
                };

                let m = if x1 == x2 && y1 == y2 {
                    let x1_sq = x1.mul_mod(&x1, p_nz);
                    let three_x1_sq = x1_sq.mul_mod(&three, p_nz);
                    let num = three_x1_sq.add_mod(&self.curve.a, p_nz);

                    let den = y1.mul_mod(&two, p_nz);
                    let den_inv = modinv(&den, p_nz).unwrap();

                    num.mul_mod(&den_inv, p_nz)
                } else {
                    let num = y2.sub_mod(&y1, p_nz);
                    let den = x2.sub_mod(&x1, p_nz);
                    let den_inv = modinv(&den, p_nz).unwrap();

                    num.mul_mod(&den_inv, p_nz)
                };

                let m_sq = m.mul_mod(&m, p_nz);
                let x3 = m_sq.sub_mod(&x1, p_nz).sub_mod(&x2, p_nz);

                let x1_x3 = x1.sub_mod(&x3, p_nz);
                let y3 = m.mul_mod(&x1_x3, p_nz).sub_mod(&y1, p_nz);

                Self {
                    point: Point::Point { x: x3, y: y3 },
                    curve: self.curve,
                }
            } else {
                self.clone()
            }
        } else {
            rhs.clone()
        }
    }

    fn identity(&self) -> Self {
        Self {
            point: Point::O,
            curve: self.curve,
        }
    }

    fn inverse(&self) -> Self {
        if let Point::Point { x, y } = self.point {
            let p_nz = self.curve.p.as_nz_ref();
            let y = U2048::ZERO.sub_mod(&y, p_nz);
            let point = Point::Point { x, y };
            Self {
                point,
                curve: self.curve,
            }
        } else {
            self.clone()
        }
    }

    fn coord(&self) -> Option<U2048> {
        match self.point {
            Point::O => None,
            Point::Point { x, .. } => Some(x),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct MontgomeryCurve {
    a: U2048,
    b: U2048,
    p: OddUint<{ U2048::LIMBS }>,
}

impl MontgomeryCurve {
    pub fn new(a: U2048, b: U2048, p: OddUint<{ U2048::LIMBS }>) -> Self {
        Self { a, b, p }
    }
}

#[derive(Clone, PartialEq)]
pub struct MontgomeryCurvePoint<'a> {
    pub u: U2048,
    curve: &'a MontgomeryCurve,
}

impl<'a> MontgomeryCurvePoint<'a> {
    pub fn new(u: U2048, curve: &'a MontgomeryCurve) -> Self {
        Self { u, curve }
    }
}

impl MontgomeryCurvePoint<'_> {
    pub fn ladder(&self, pow: &U2048) -> Self {
        fn cswap(a: U2048, b: U2048, condition: bool) -> (U2048, U2048) {
            if condition { (b, a) } else { (a, b) }
        }

        let p_nz = self.curve.p.as_nz_ref();
        let a = self.curve.a;
        let (mut u2, mut w2) = (U2048::ONE, U2048::ZERO);
        let (mut u3, mut w3) = (self.u, U2048::ONE);

        let len = pow.bits_vartime();
        for i in (0..len).rev() {
            let cond = (pow.shr_vartime(i) & U2048::ONE) == U2048::ONE;
            (u2, u3) = cswap(u2, u3, cond);
            (w2, w3) = cswap(w2, w3, cond);
            let (u3_new, w3_new) = (
                u2.mul_mod_vartime(&u3, p_nz)
                    .sub_mod(&w2.mul_mod_vartime(&w3, p_nz), p_nz)
                    .square_mod_vartime(p_nz),
                self.u.mul_mod_vartime(
                    &u2.mul_mod_vartime(&w3, p_nz)
                        .sub_mod(&w2.mul_mod_vartime(&u3, p_nz), p_nz)
                        .square_mod_vartime(p_nz),
                    p_nz,
                ),
            );
            (u3, w3) = (u3_new, w3_new);
            let (u2_new, w2_new) = (
                u2.square_mod_vartime(p_nz)
                    .sub_mod(&w2.square_mod_vartime(p_nz), p_nz)
                    .square_mod_vartime(p_nz),
                u2.square_mod_vartime(p_nz)
                    .add_mod(&w2.square_mod_vartime(p_nz), p_nz)
                    .add_mod(
                        &u2.mul_mod_vartime(&w2, p_nz).mul_mod_vartime(&a, p_nz),
                        p_nz,
                    )
                    .mul_mod_vartime(&bigint(4), p_nz)
                    .mul_mod_vartime(&u2, p_nz)
                    .mul_mod_vartime(&w2, p_nz),
            );
            (u2, w2) = (u2_new, w2_new);
            (u2, u3) = cswap(u2, u3, cond);
            (w2, w3) = cswap(w2, w3, cond);
        }

        let u = modexp(&w2, &self.curve.p.sub_mod(&bigint(2), p_nz), &self.curve.p)
            .mul_mod_vartime(&u2, p_nz);

        Self {
            u,
            curve: self.curve,
        }
    }
}

pub fn ecdsa_sign(
    d: &U2048,
    n: &NonZero<U2048>,
    g: &EllipticCurvePoint,
    message: &[u8],
) -> (U2048, U2048) {
    let hash = sha_1(message);
    let hash = bigint_hex(&hex_encode(&hash));

    loop {
        let k = random_biguint(n);
        let r = match g.mul(&k).coord() {
            Some(r) => r.rem_vartime(n),
            None => {
                continue;
            }
        };

        let k_1 = modinv(&k, n).unwrap();
        let hxr = hash.add_mod(&d.mul_mod(&r, n), n);
        let s = k_1.mul_mod_vartime(&hxr, n);
        if s != U2048::ZERO {
            return (r, s);
        }
    }
}

pub fn ecdsa_verify(
    q: &EllipticCurvePoint,
    signature: &(U2048, U2048),
    n: &NonZero<U2048>,
    g: &EllipticCurvePoint,
    message: &[u8],
) -> bool {
    let (r, s) = signature;
    if *r == U2048::ZERO || *s == U2048::ZERO {
        return false;
    }

    let hash = sha_1(message);
    let hash = bigint_hex(&hex_encode(&hash));

    let w = modinv(s, n).unwrap();
    let u1 = hash.mul_mod(&w, n);
    let u2 = r.mul_mod(&w, n);
    if let Some(v) = g.mul(&u1).add(&q.mul(&u2)).coord() {
        let v = v.rem_vartime(n);
        *r == v
    } else {
        false
    }
}

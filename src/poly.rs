use std::ops::{Add, Mul};

// less significant bits = lower degree
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Polynomial(u128);

const MODULUS: Polynomial = Polynomial(0b10000111);

impl<'a, 'b> Add<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: &'b Polynomial) -> Self::Output {
        Polynomial(self.0 ^ rhs.0)
    }
}

impl<'a, 'b> Mul<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: &'b Polynomial) -> Self::Output {
        self.mul_mod(rhs, &MODULUS)
    }
}

impl Polynomial {
    pub fn new(val: u128) -> Self {
        Self(val)
    }

    pub fn div_mod(&self, denom: &Self) -> (Self, Self) {
        if denom.0 == 0 {
            panic!("divide by zero");
        }
        let mut q: u128 = 0;
        let mut r = self.0;

        while r != 0 && r.ilog2() >= denom.0.ilog2() {
            let d = r.ilog2() - denom.0.ilog2();
            q = q ^ (1 << d);
            r = r ^ (denom.0 << d);
        }

        (Self(q), Self(r))
    }

    #[inline]
    fn shl_carry(i: u128) -> (u128, bool) {
        (i << 1, i & (1u128 << 127) != 0)
    }

    // modulus implicitly assumed to be missing the x^128 term
    pub fn mul_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let mut p: u128 = 0;
        let mut a = self.0;
        let mut b = rhs.0;

        while a > 0 {
            if a & 1 == 1 {
                p = p ^ b;
            }
            a = a >> 1;
            let (nb, carry) = Self::shl_carry(b);

            b = if carry { nb ^ modulus.0 } else { nb }
        }

        Self(p)
    }
}

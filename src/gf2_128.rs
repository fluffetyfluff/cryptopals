use std::ops::{Add, Div, Mul, Neg, Sub};

use derive_more::Deref;

use crate::primitives::Block;

// less significant bits = lower degree
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct GF2_128(u128);

const MODULUS: GF2_128 = GF2_128(0b10000111);

impl<'a, 'b> Add<&'b GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    fn add(self, rhs: &'b GF2_128) -> Self::Output {
        GF2_128(self.0 ^ rhs.0)
    }
}

impl<'a> Add<GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn add(self, rhs: GF2_128) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a> Add<&'a GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn add(self, rhs: &'a GF2_128) -> Self::Output {
        (&self).add(rhs)
    }
}

impl Add<GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn add(self, rhs: GF2_128) -> Self::Output {
        (&self).add(&rhs)
    }
}

impl<'a, 'b> Mul<&'b GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    fn mul(self, rhs: &'b GF2_128) -> Self::Output {
        self.mul_mod(rhs, &MODULUS)
    }
}

impl<'a> Mul<GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn mul(self, rhs: GF2_128) -> Self::Output {
        self.mul(&rhs)
    }
}

impl<'a> Mul<&'a GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn mul(self, rhs: &'a GF2_128) -> Self::Output {
        (&self).mul(rhs)
    }
}

impl Mul<GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn mul(self, rhs: GF2_128) -> Self::Output {
        (&self).mul(&rhs)
    }
}

impl<'a> Neg for &'a GF2_128 {
    type Output = GF2_128;

    fn neg(self) -> Self::Output {
        self.clone()
    }
}

impl Neg for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn neg(self) -> Self::Output {
        (&self).neg()
    }
}

impl<'a, 'b> Sub<&'b GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    // every number is its own inverse in characteristic 2
    fn sub(self, rhs: &'b GF2_128) -> Self::Output {
        self + rhs
    }
}

impl<'a> Sub<GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn sub(self, rhs: GF2_128) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<'a> Sub<&'a GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn sub(self, rhs: &'a GF2_128) -> Self::Output {
        (&self).sub(rhs)
    }
}

impl Sub<GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn sub(self, rhs: GF2_128) -> Self::Output {
        (&self).sub(&rhs)
    }
}

impl<'a, 'b> Div<&'b GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    fn div(self, denom: &'b GF2_128) -> Self::Output {
        self.mul(denom.inverse())
    }
}

impl<'a> Div<GF2_128> for &'a GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn div(self, denom: GF2_128) -> Self::Output {
        self.div(&denom)
    }
}

impl<'a> Div<&'a GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn div(self, denom: &'a GF2_128) -> Self::Output {
        (&self).div(denom)
    }
}

impl Div<GF2_128> for GF2_128 {
    type Output = GF2_128;

    #[inline]
    fn div(self, denom: GF2_128) -> Self::Output {
        (&self).div(&denom)
    }
}

impl GF2_128 {
    pub const ZERO: GF2_128 = GF2_128(0);
    pub const ONE: GF2_128 = GF2_128(1);

    pub const fn new(val: u128) -> Self {
        Self(val)
    }

    pub fn from_block(block: Block) -> Self {
        Self(u128::from_be_bytes(block))
    }

    pub fn to_block(&self) -> Block {
        self.0.to_be_bytes()
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
    const fn shl_carry(i: u128) -> (u128, bool) {
        (i << 1, i & (1u128 << 127) != 0)
    }

    // modulus implicitly assumed to be missing the x^128 term
    pub const fn mul_mod(&self, rhs: &Self, modulus: &Self) -> Self {
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

    pub fn inverse(&self) -> Self {
        let mut r = Self::new(1);
        for _ in 0..127 {
            r = r * r * self;
        }
        r * r
    }

    pub fn sqrt(&self) -> Self {
        let mut r = *self;
        for _ in 0..127 {
            r = r * r;
        }
        r
    }

    pub fn get_bit(&self, index: usize) -> bool {
        self.0 & (1 << index) != 0
    }
}

// each element is one column, stored left to right
#[derive(Debug, Deref, Copy, Clone)]
pub struct Matrix([GF2_128; 128]);

impl<'a, 'b> Mul<&'b GF2_128> for &'a Matrix {
    type Output = GF2_128;

    fn mul(self, rhs: &GF2_128) -> Self::Output {
        let mut ans = GF2_128::ZERO;
        for i in 0..128 {
            if rhs.get_bit(i) {
                ans = ans + self[i];
            }
        }
        ans
    }
}

impl<'a> Mul<GF2_128> for &'a Matrix {
    type Output = GF2_128;

    #[inline]
    fn mul(self, rhs: GF2_128) -> Self::Output {
        self.mul(&rhs)
    }
}

impl<'a> Mul<&'a GF2_128> for Matrix {
    type Output = GF2_128;

    #[inline]
    fn mul(self, rhs: &'a GF2_128) -> Self::Output {
        (&self).mul(rhs)
    }
}

impl Mul<GF2_128> for Matrix {
    type Output = GF2_128;

    #[inline]
    fn mul(self, rhs: GF2_128) -> Self::Output {
        (&self).mul(&rhs)
    }
}

impl Matrix {
    pub const SQUARE_MATRIX: Self = {
        let mut square_matrix = [GF2_128::ZERO; 128];
        let mut i = 0;
        while i < 128 {
            let basis_vec = GF2_128::new(1 << i);
            square_matrix[i] = basis_vec.mul_mod(&basis_vec, &MODULUS);
            i += 1;
        }
        Self::new(square_matrix)
    };

    pub const fn new(input: [GF2_128; 128]) -> Self {
        Self(input)
    }
}

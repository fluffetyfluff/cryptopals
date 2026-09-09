use derive_more::Index;

use crate::gf2_128::GF2_128;

#[derive(Clone, Debug, PartialEq, Index)]
pub struct GFPolynomial(Vec<GF2_128>);

impl GFPolynomial {
    pub const ZERO: GFPolynomial = GFPolynomial(Vec::new());

    pub fn new(mut v: Vec<GF2_128>) -> Self {
        while v.last() == Some(&GF2_128::ZERO) {
            v.pop();
        }
        Self(v)
    }

    pub fn constant(c: GF2_128) -> Self {
        Self::new(vec![c])
    }

    pub fn degree(&self) -> i32 {
        self.0.len() as i32 - 1
    }

    pub fn leading_coefficient(&self) -> GF2_128 {
        *self.0.last().unwrap_or(&GF2_128::ZERO)
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut ans: Vec<GF2_128> = Vec::new();
        let (shorter, longer) = if self.degree() < rhs.degree() {
            (self, rhs)
        } else {
            (rhs, self)
        };
        for i in 0..(shorter.degree() + 1) as usize {
            ans.push(shorter[i] + longer[i]);
        }
        ans.extend_from_slice(&longer.0[(shorter.degree() + 1) as usize..]);
        Self::new(ans)
    }

    pub fn neg(&self) -> Self {
        let ans = self.0.iter().map(|x| -x).collect();
        Self::new(ans)
    }

    fn mul_polynomial(&self, shift: usize) -> Self {
        let mut new = vec![GF2_128::ZERO; shift];
        new.extend_from_slice(&self.0);
        Self::new(new)
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let mut ans = Self::ZERO;
        let degree = rhs.degree();
        if degree < 0 {
            return ans;
        }
        for i in (0..=degree).rev() {
            ans = ans.mul_polynomial(1);
            ans = ans.add(&self.scalar_mul(&rhs[i as usize]));
        }
        ans
    }

    pub fn scalar_mul(&self, scalar: &GF2_128) -> Self {
        Self::new(self.0.iter().map(|x| x * scalar).collect())
    }

    pub fn div(&self, denom: &Self) -> (Self, Self) {
        assert!(denom.degree() >= 0);
        let mut quot = Self::ZERO;
        let mut rem = self.clone();

        while rem != Self::ZERO && rem.degree() >= denom.degree() {
            let t = Self::constant(rem.leading_coefficient() / denom.leading_coefficient());
            let t = t.mul_polynomial((rem.degree() - denom.degree()) as usize);
            quot = quot.add(&t);
            rem = rem.add(&denom.mul(&t.neg()));
        }

        (quot, rem)
    }
}

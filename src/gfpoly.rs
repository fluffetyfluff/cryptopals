use derive_more::{Index, IndexMut};

use crate::gf2_128::GF2_128;

#[derive(Clone, Debug, PartialEq, Index, IndexMut)]
pub struct GFPolynomial(Vec<GF2_128>);

impl GFPolynomial {
    pub fn degree(&self) -> i32 {
        let deg = self.0.iter().rposition(|c| *c != GF2_128::ZERO);
        deg.map_or(-1, |x| x as i32)
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let (mut ans, other) = if self.degree() > rhs.degree() {
            (self.clone(), rhs)
        } else {
            (rhs.clone(), self)
        };
        for i in 0..other.0.len() {
            ans[i] = ans[i] + other[i];
        }
        ans
    }

    fn mul_polynomial(&self, degree: usize) -> Self {
        let mut new = vec![GF2_128::ZERO; degree];
        new.extend_from_slice(&self.0);
        Self(new)
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let mut ans = GFPolynomial(Vec::new());
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
        Self(self.0.iter().map(|x| x * scalar).collect())
    }
}

use malachite::Integer;
use malachite::base::num::arithmetic::traits::Abs;
use malachite::base::num::basic::traits::Zero;
use malachite::{Rational, base::num::conversion::traits::RoundingInto};
use std::cmp::max;
use std::ops::{Add, Deref, Mul, Sub};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatioVec(Box<[Rational]>);

// ==========================================
// 1. Deref Implementation (Provides .len(), indexing, etc.)
// ==========================================

impl Deref for RatioVec {
    type Target = [Rational];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ==========================================
// 2. Vector Addition: RatioVec + RatioVec
// ==========================================

impl<'a, 'b> Add<&'b RatioVec> for &'a RatioVec {
    type Output = RatioVec;

    fn add(self, rhs: &'b RatioVec) -> Self::Output {
        assert_eq!(self.len(), rhs.len());

        let sum: Box<[Rational]> = self.iter().zip(rhs.iter()).map(|(a, b)| a + b).collect();

        RatioVec(sum)
    }
}

impl<'a> Add<&'a RatioVec> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn add(self, rhs: &'a RatioVec) -> Self::Output {
        &self + rhs
    }
}

impl<'a> Add<RatioVec> for &'a RatioVec {
    type Output = RatioVec;
    #[inline]
    fn add(self, rhs: RatioVec) -> Self::Output {
        self + &rhs
    }
}

impl Add<RatioVec> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn add(self, rhs: RatioVec) -> Self::Output {
        &self + &rhs
    }
}

// ==========================================
// 3. Vector Subtraction: RatioVec - RatioVec
// ==========================================

impl<'a, 'b> Sub<&'b RatioVec> for &'a RatioVec {
    type Output = RatioVec;

    fn sub(self, rhs: &'b RatioVec) -> Self::Output {
        assert_eq!(self.len(), rhs.len());

        let diff: Box<[Rational]> = self.iter().zip(rhs.iter()).map(|(a, b)| a - b).collect();

        RatioVec(diff)
    }
}

impl<'a> Sub<&'a RatioVec> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn sub(self, rhs: &'a RatioVec) -> Self::Output {
        &self - rhs
    }
}

impl<'a> Sub<RatioVec> for &'a RatioVec {
    type Output = RatioVec;
    #[inline]
    fn sub(self, rhs: RatioVec) -> Self::Output {
        self - &rhs
    }
}

impl Sub<RatioVec> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn sub(self, rhs: RatioVec) -> Self::Output {
        &self - &rhs
    }
}

// ==========================================
// 4. Vector Dot Product: RatioVec * RatioVec
// ==========================================

impl<'a, 'b> Mul<&'b RatioVec> for &'a RatioVec {
    type Output = Rational;

    fn mul(self, rhs: &'b RatioVec) -> Self::Output {
        assert_eq!(self.len(), rhs.len());

        self.iter()
            .zip(rhs.iter())
            .map(|(a, b)| a * b)
            .fold(Rational::ZERO, |acc, e| acc + e)
    }
}

impl<'a> Mul<&'a RatioVec> for RatioVec {
    type Output = Rational;
    #[inline]
    fn mul(self, rhs: &'a RatioVec) -> Self::Output {
        &self * rhs
    }
}

impl<'a> Mul<RatioVec> for &'a RatioVec {
    type Output = Rational;
    #[inline]
    fn mul(self, rhs: RatioVec) -> Self::Output {
        self * &rhs
    }
}

impl Mul<RatioVec> for RatioVec {
    type Output = Rational;
    #[inline]
    fn mul(self, rhs: RatioVec) -> Self::Output {
        &self * &rhs
    }
}

// ==========================================
// 5. Scalar Multiplication: RatioVec * Rational
// ==========================================

impl<'a, 'b> Mul<&'b Rational> for &'a RatioVec {
    type Output = RatioVec;

    fn mul(self, rhs: &'b Rational) -> Self::Output {
        let sum: Box<[Rational]> = self.iter().map(|x| x * rhs).collect();
        RatioVec(sum)
    }
}

impl<'a> Mul<&'a Rational> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn mul(self, rhs: &'a Rational) -> Self::Output {
        &self * rhs
    }
}

impl<'a> Mul<Rational> for &'a RatioVec {
    type Output = RatioVec;
    #[inline]
    fn mul(self, rhs: Rational) -> Self::Output {
        self * &rhs
    }
}

impl Mul<Rational> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn mul(self, rhs: Rational) -> Self::Output {
        &self * &rhs
    }
}

// ==========================================
// 6. Constructors and Idiomatic Conversion Traits
// ==========================================

impl RatioVec {
    pub fn is_zero(&self) -> bool {
        self.iter().all(|x| *x == Rational::ZERO)
    }

    pub fn new(slice: Box<[Rational]>) -> Self {
        Self(slice)
    }

    pub fn new_zero(len: usize) -> Self {
        Self(vec![Rational::ZERO; len].into_boxed_slice())
    }

    pub fn proj(&self, v: &RatioVec) -> RatioVec {
        if self.is_zero() {
            Self::new_zero(self.len())
        } else {
            let m = (self * v) / (self * self);
            self * m
        }
    }
}

impl From<Vec<Rational>> for RatioVec {
    fn from(vec: Vec<Rational>) -> Self {
        Self(vec.into_boxed_slice())
    }
}

impl FromIterator<Rational> for RatioVec {
    fn from_iter<I: IntoIterator<Item = Rational>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

// ==========================================
// 7. Algorithms
// ==========================================

pub fn gram_schmidt(basis: &[RatioVec]) -> Vec<RatioVec> {
    let mut q: Vec<RatioVec> = Vec::new();

    for v in basis {
        let proj_sum = q
            .iter()
            .map(|u| u.proj(v))
            .fold(RatioVec::new_zero(v.len()), |acc, e| acc + e);

        let u = v - proj_sum;
        q.push(u);
    }

    q
}

fn round_rational(r: &Rational) -> Rational {
    let nearest: Integer = r
        .rounding_into(malachite::base::rounding_modes::RoundingMode::Nearest)
        .0;
    Rational::from(nearest)
}

pub fn lll(basis: &[RatioVec], delta: Rational) -> Vec<RatioVec> {
    let mut b = Vec::new();
    b.extend_from_slice(basis);
    let mut q = gram_schmidt(basis);

    let mut k = 1;
    while k < b.len() {
        for j in (0..k).rev() {
            let m = (&b[k] * &q[j]) / (&q[j] * &q[j]);
            if (&m).abs() > Rational::from_signeds(1, 2) {
                b[k] = &b[k] - &b[j] * round_rational(&m);
                q = gram_schmidt(&b);
            }
        }

        let m = (&b[k] * &q[k - 1]) / (&q[k - 1] * &q[k - 1]);
        if &q[k] * &q[k] >= (&delta - (&m * &m)) * (&q[k - 1] * &q[k - 1]) {
            k = k + 1
        } else {
            b.swap(k, k - 1);
            q = gram_schmidt(&b);
            k = max(k - 1, 1);
        }
    }

    b
}

use crypto_ratio::RatioU2048;
use std::ops::{Add, Mul};

pub struct RatioVec(Vec<RatioU2048>);

impl<'a, 'b> Add<&'b RatioVec> for &'a RatioVec {
    type Output = RatioVec;

    fn add(self, rhs: &'b RatioVec) -> Self::Output {
        assert!(self.len() == rhs.len());

        let sum: Vec<RatioU2048> = self
            .0
            .iter()
            .zip(rhs.0.iter())
            .map(|(a, b)| a + b)
            .collect();

        RatioVec(sum)
    }
}

impl<'a> Add<&'a RatioVec> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn add(self, rhs: &'a RatioVec) -> Self::Output {
        (&self).add(rhs)
    }
}

impl<'a> Add<RatioVec> for &'a RatioVec {
    type Output = RatioVec;
    #[inline]
    fn add(self, rhs: RatioVec) -> Self::Output {
        self.add(&rhs)
    }
}

impl Add<RatioVec> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn add(self, rhs: RatioVec) -> Self::Output {
        (&self).add(&rhs)
    }
}

impl<'a, 'b> Mul<&'b RatioVec> for &'a RatioVec {
    type Output = RatioU2048;

    fn mul(self, rhs: &'b RatioVec) -> Self::Output {
        assert!(self.len() == rhs.len());

        let sum = self
            .0
            .iter()
            .zip(rhs.0.iter())
            .map(|(a, b)| a * b)
            .fold(RatioU2048::zero(), |acc, e| acc + e);

        sum
    }
}

impl<'a> Mul<&'a RatioVec> for RatioVec {
    type Output = RatioU2048;
    #[inline]
    fn mul(self, rhs: &'a RatioVec) -> Self::Output {
        (&self).mul(rhs)
    }
}

impl<'a> Mul<RatioVec> for &'a RatioVec {
    type Output = RatioU2048;
    #[inline]
    fn mul(self, rhs: RatioVec) -> Self::Output {
        self.mul(&rhs)
    }
}

impl Mul<RatioVec> for RatioVec {
    type Output = RatioU2048;
    #[inline]
    fn mul(self, rhs: RatioVec) -> Self::Output {
        (&self).mul(&rhs)
    }
}

impl<'a, 'b> Mul<&'b RatioU2048> for &'a RatioVec {
    type Output = RatioVec;

    fn mul(self, rhs: &'b RatioU2048) -> Self::Output {
        let sum: Vec<RatioU2048> = self.0.iter().map(|x| x * &rhs).collect();

        RatioVec(sum)
    }
}

impl<'a> Mul<&'a RatioU2048> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn mul(self, rhs: &'a RatioU2048) -> Self::Output {
        (&self).mul(rhs)
    }
}

impl<'a> Mul<RatioU2048> for &'a RatioVec {
    type Output = RatioVec;
    #[inline]
    fn mul(self, rhs: RatioU2048) -> Self::Output {
        self.mul(&rhs)
    }
}

impl Mul<RatioU2048> for RatioVec {
    type Output = RatioVec;
    #[inline]
    fn mul(self, rhs: RatioU2048) -> Self::Output {
        (&self).mul(&rhs)
    }
}

impl RatioVec {
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(RatioU2048::is_zero)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn new(vec: Vec<RatioU2048>) -> Self {
        Self(vec)
    }

    pub fn proj(&self, v: &RatioVec) -> RatioVec {
        if self.is_zero() {
            Self::new(vec![RatioU2048::zero(); self.len()])
        } else {
            let m = (self * v) / (self * self);
            self * m
        }
    }
}

use crate::crypto::{Error, Result};
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Sub, Mul, Div, Rem, Shl, Shr, BitAnd, BitOr, BitXor};

#[derive(Clone, PartialEq, Eq)]
pub struct BigNum {
    limbs: Vec<u64>,
}

impl BigNum {
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            BigNum { limbs: vec![0] }
        } else {
            BigNum { limbs: vec![value] }
        }
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return BigNum::zero();
        }

        let mut limbs = Vec::new();
        let mut chunks = bytes.rchunks_exact(8);
        for chunk in &mut chunks {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(chunk);
            limbs.push(u64::from_be_bytes(arr));
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut arr = [0u8; 8];
            let offset = 8 - remainder.len();
            arr[offset..].copy_from_slice(remainder);
            limbs.push(u64::from_be_bytes(arr));
        }

        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }

        BigNum { limbs }
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return BigNum::zero();
        }

        let mut limbs = Vec::new();
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(chunk);
            limbs.push(u64::from_le_bytes(arr));
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut arr = [0u8; 8];
            arr[..remainder.len()].copy_from_slice(remainder);
            limbs.push(u64::from_le_bytes(arr));
        }

        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }

        BigNum { limbs }
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::new();
        let mut started = false;
        for &limb in self.limbs.iter().rev() {
            let limb_bytes = limb.to_be_bytes();
            if !started {
                let mut first_nonzero = 0;
                while first_nonzero < 8 && limb_bytes[first_nonzero] == 0 {
                    first_nonzero += 1;
                }

                if first_nonzero < 8 {
                    bytes.extend_from_slice(&limb_bytes[first_nonzero..]);
                    started = true;
                }
            } else {
                bytes.extend_from_slice(&limb_bytes);
            }
        }

        if bytes.is_empty() {
            vec![0]
        } else {
            bytes
        }
    }

    pub fn to_bytes_le(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &limb in &self.limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }

        while bytes.len() > 1 && bytes.last() == Some(&0) {
            bytes.pop();
        }

        bytes
    }

    pub fn zero() -> Self {
        BigNum { limbs: vec![0] }
    }

    pub fn one() -> Self {
        BigNum { limbs: vec![1] }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&limb| limb == 0)
    }

    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }

    pub fn bit_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let last_limb = self.limbs[self.limbs.len() - 1];
        let last_limb_bits = 64 - last_limb.leading_zeros() as usize;
        (self.limbs.len() - 1) * 64 + last_limb_bits
    }

    pub fn bit(&self, pos: usize) -> bool {
        let limb_idx = pos / 64;
        let bit_idx = pos % 64;
        if limb_idx >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_idx] >> bit_idx) & 1 == 1
        }
    }

    pub fn set_bit(&mut self, pos: usize, value: bool) {
        let limb_idx = pos / 64;
        let bit_idx = pos % 64;
        while self.limbs.len() <= limb_idx {
            self.limbs.push(0);
        }

        if value {
            self.limbs[limb_idx] |= 1u64 << bit_idx;
        } else {
            self.limbs[limb_idx] &= !(1u64 << bit_idx);
        }

        self.normalize();
    }

    pub fn mod_exp(&self, exponent: &BigNum, modulus: &BigNum) -> Result<BigNum> {
        if modulus.is_zero() {
            return Err(Error::CryptoError("Division by zero in mod_exp".to_string()));
        }

        let mut result = BigNum::one();
        let mut base = self.clone() % modulus.clone();
        let mut exp = exponent.clone();
        while !exp.is_zero() {
            if exp.is_odd() {
                result = (result * base.clone()) % modulus.clone();
            }

            base = (base.clone() * base.clone()) % modulus.clone();
            exp = exp >> 1;
        }

        Ok(result)
    }

    pub fn mod_inverse(&self, modulus: &BigNum) -> Result<BigNum> {
        let (gcd, x, _) = Self::extended_gcd(self, modulus);
        if !gcd.is_one() {
            return Err(Error::CryptoError("No modular inverse exists".to_string()));
        }

        Ok(x.modulo(modulus))
    }

    pub fn modulo(&self, modulus: &BigNum) -> BigNum {
        let rem = self.clone() % modulus.clone();
        if rem.limbs[0] & (1u64 << 63) != 0 {
            rem + modulus.clone()
        } else {
            rem
        }
    }

    // Greatest Common Divisor using Euclidean Algorithm
    pub fn gcd(&self, other: &BigNum) -> BigNum {
        let mut a = self.clone();
        let mut b = other.clone();
        while !b.is_zero() {
            let temp = b.clone();
            b = a % b;
            a = temp;
        }

        a
    }

    pub fn is_probably_prime(&self, rounds: usize) -> Result<bool> {
        use crate::crypto::random::generate_random;

        if self <= &BigNum::one() {
            return Ok(false);
        }

        if self == &BigNum::from_u64(2) || self == &BigNum::from_u64(3) {
            return Ok(true);
        }

        if self.is_even() {
            return Ok(false);
        }

        let n_minus_1 = self.clone() - BigNum::one();
        let mut r = 0;
        let mut d = n_minus_1.clone();
        while d.is_even() {
            d = d >> 1;
            r += 1;
        }

        'witness: for _ in 0..rounds {
            let bytes_needed = (self.bit_length() + 7) / 8;
            let random_bytes = generate_random(bytes_needed)?;
            let mut a = BigNum::from_bytes_be(&random_bytes) % (self.clone() - BigNum::from_u64(3));
            a = a + BigNum::from_u64(2);

            let mut x = a.mod_exp(&d, self)?;
            if x.is_one() || x == n_minus_1 {
                continue 'witness;
            }

            for _ in 0..(r - 1) {
                x = x.mod_exp(&BigNum::from_u64(2), self)?;
                if x == n_minus_1 {
                    continue 'witness;
                }
            }

            return Ok(false);
        }

        Ok(true)
    }

    pub fn generate_prime(bits: usize, rounds: usize) -> Result<BigNum> {
        use crate::crypto::random::generate_random;
        if bits < 2 {
            return Err(Error::CryptoError("Bit length must be at least 2".to_string()));
        }

        loop {
            let bytes_needed = (bits + 7) / 8;
            let random_bytes = generate_random(bytes_needed)?;
            let mut candidate = BigNum::from_bytes_be(&random_bytes);

            candidate.set_bit(bits - 1, true);
            candidate.set_bit(0, true);
            if candidate.is_probably_prime(rounds)? {
                return Ok(candidate);
            }
        }
    }

    // Euclidian Algorithm -- returns (gcd, x, y) where gcd = ax + by
    fn extended_gcd(&self, other: &BigNum) -> (BigNum, BigNum, BigNum) {
        if other.is_zero() {
            return (self.clone(), BigNum::one(), BigNum::zero());
        }

        let (gcd, x1, y1) = other.extended_gcd(&(self.clone() % other.clone()));
        let x = y1.clone();
        let y = x1 - (self.clone() / other.clone()) * y1;

        (gcd, x, y)
    }

    fn normalize(&mut self) {
        while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }
}

impl fmt::Debug for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BigNum(0x{})", hex::encode(&self.to_bytes_be()))
    }
}

impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes_be()))
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigNum {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }

        for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            match a.cmp(b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        Ordering::Equal
    }
}

impl Add for BigNum {
    type Output = BigNum;

    fn add(self, other: BigNum) -> BigNum {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;
        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);

            let (sum1, overflow1) = a.overflowing_add(b);
            let (sum2, overflow2) = sum1.overflowing_add(carry);

            result.push(sum2);
            carry = (overflow1 as u64) + (overflow2 as u64);
        }

        if carry > 0 {
            result.push(carry);
        }

        let mut bn = BigNum { limbs: result };
        bn.normalize();

        bn
    }
}

impl Sub for BigNum {
    type Output = BigNum;

    fn sub(self, other: BigNum) -> BigNum {
        if self < other {
            // For unsigned arithmetic, return zero if result is negative
            return BigNum::zero();
        }

        let mut result = self.limbs.clone();
        let mut borrow = 0u64;
        for i in 0..result.len() {
            let b = other.limbs.get(i).copied().unwrap_or(0);
            let (diff1, underflow1) = result[i].overflowing_sub(b);
            let (diff2, underflow2) = diff1.overflowing_sub(borrow);

            result[i] = diff2;
            borrow = (underflow1 as u64) + (underflow2 as u64);
        }

        let mut bn = BigNum { limbs: result };
        bn.normalize();

        bn
    }
}

impl Mul for BigNum {
    type Output = BigNum;

    fn mul(self, other: BigNum) -> BigNum {
        if self.is_zero() || other.is_zero() {
            return BigNum::zero();
        }

        let mut result = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let product = (a as u128) * (b as u128) + (result[i + j] as u128) + carry;
                result[i + j] = product as u64;
                carry = product >> 64;
            }

            if carry > 0 {
                result[i + other.limbs.len()] = carry as u64;
            }
        }

        let mut bn = BigNum { limbs: result };
        bn.normalize();

        bn
    }
}

impl Div for BigNum {
    type Output = BigNum;

    fn div(self, other: BigNum) -> BigNum {
        self.div_rem(&other).0
    }
}

impl Rem for BigNum {
    type Output = BigNum;

    fn rem(self, other: BigNum) -> BigNum {
        self.div_rem(&other).1
    }
}

impl BigNum {

    // Division with remainder
    fn div_rem(&self, divisor: &BigNum) -> (BigNum, BigNum) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        if self < divisor {
            return (BigNum::zero(), self.clone());
        }

        if divisor.is_one() {
            return (self.clone(), BigNum::zero());
        }

        let mut quotient = BigNum::zero();
        let mut remainder = BigNum::zero();
        for i in (0..self.bit_length()).rev() {
            remainder = remainder << 1;
            if self.bit(i) {
                remainder.set_bit(0, true);
            }

            if remainder >= *divisor {
                remainder = remainder - divisor.clone();
                quotient.set_bit(i, true);
            }
        }

        (quotient, remainder)
    }
}

impl Shl<usize> for BigNum {
    type Output = BigNum;

    fn shl(self, shift: usize) -> BigNum {
        if self.is_zero() || shift == 0 {
            return self;
        }

        let limb_shift = shift / 64;
        let bit_shift = shift % 64;

        let mut result = vec![0u64; limb_shift];
        result.extend(&self.limbs);
        if bit_shift > 0 {
            let mut carry = 0u64;
            for limb in result.iter_mut().skip(limb_shift) {
                let new_carry = *limb >> (64 - bit_shift);
                *limb = (*limb << bit_shift) | carry;
                carry = new_carry;
            }
            if carry > 0 {
                result.push(carry);
            }
        }

        let mut bn = BigNum { limbs: result };
        bn.normalize();
        bn
    }
}

impl Shr<usize> for BigNum {
    type Output = BigNum;

    fn shr(self, shift: usize) -> BigNum {
        if self.is_zero() || shift == 0 {
            return self;
        }

        let limb_shift = shift / 64;
        let bit_shift = shift % 64;
        if limb_shift >= self.limbs.len() {
            return BigNum::zero();
        }

        let mut result: Vec<u64> = self.limbs.iter().skip(limb_shift).copied().collect();
        if bit_shift > 0 && !result.is_empty() {
            let mut carry = 0u64;
            for limb in result.iter_mut().rev() {
                let new_carry = *limb << (64 - bit_shift);
                *limb = (*limb >> bit_shift) | carry;
                carry = new_carry;
            }
        }

        let mut bn = BigNum { limbs: result };
        bn.normalize();

        bn
    }
}

impl BitAnd for BigNum {
    type Output = BigNum;

    fn bitand(self, other: BigNum) -> BigNum {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut result = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            result.push(a & b);
        }

        BigNum { limbs: result }
    }
}

impl BitOr for BigNum {
    type Output = BigNum;

    fn bitor(self, other: BigNum) -> BigNum {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut result = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            result.push(a | b);
        }

        BigNum { limbs: result }
    }
}

impl BitXor for BigNum {
    type Output = BigNum;

    fn bitxor(self, other: BigNum) -> BigNum {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut result = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            result.push(a ^ b);
        }

        BigNum { limbs: result }
    }
}

// Helper for hex encoding/decoding
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        let bn = BigNum::from_u64(42);
        assert_eq!(bn.limbs, vec![42]);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let bn = BigNum::from_bytes_be(&bytes);
        assert_eq!(bn.to_bytes_be(), bytes);
    }

    #[test]
    fn test_addition() {
        let a = BigNum::from_u64(100);
        let b = BigNum::from_u64(50);
        let c = a + b;
        assert_eq!(c, BigNum::from_u64(150));
    }

    #[test]
    fn test_subtraction() {
        let a = BigNum::from_u64(100);
        let b = BigNum::from_u64(50);
        let c = a - b;
        assert_eq!(c, BigNum::from_u64(50));
    }

    #[test]
    fn test_multiplication() {
        let a = BigNum::from_u64(12);
        let b = BigNum::from_u64(13);
        let c = a * b;
        assert_eq!(c, BigNum::from_u64(156));
    }

    #[test]
    fn test_division() {
        let a = BigNum::from_u64(156);
        let b = BigNum::from_u64(12);
        let c = a / b;
        assert_eq!(c, BigNum::from_u64(13));
    }

    #[test]
    fn test_modulo() {
        let a = BigNum::from_u64(17);
        let b = BigNum::from_u64(5);
        let c = a % b;
        assert_eq!(c, BigNum::from_u64(2));
    }

    #[test]
    fn test_mod_exp() {
        let base = BigNum::from_u64(3);
        let exp = BigNum::from_u64(4);
        let modulus = BigNum::from_u64(7);
        let result = base.mod_exp(&exp, &modulus).unwrap();
        // 3^4 mod 7 = 81 mod 7 = 4
        assert_eq!(result, BigNum::from_u64(4));
    }

    #[test]
    fn test_bit_operations() {
        let mut bn = BigNum::from_u64(0b1010);
        assert!(bn.bit(1));
        assert!(!bn.bit(0));
        assert!(bn.bit(3));
        assert!(!bn.bit(2));

        bn.set_bit(0, true);
        assert_eq!(bn, BigNum::from_u64(0b1011));
    }

    #[test]
    fn test_shifts() {
        let bn = BigNum::from_u64(0b1010);
        assert_eq!(bn.clone() << 1, BigNum::from_u64(0b10100));
        assert_eq!(bn >> 1, BigNum::from_u64(0b101));
    }

    #[test]
    fn test_comparison() {
        assert!(BigNum::from_u64(10) > BigNum::from_u64(5));
        assert!(BigNum::from_u64(5) < BigNum::from_u64(10));
        assert_eq!(BigNum::from_u64(10), BigNum::from_u64(10));
    }

    #[test]
    fn test_gcd() {
        let a = BigNum::from_u64(48);
        let b = BigNum::from_u64(18);
        assert_eq!(a.gcd(&b), BigNum::from_u64(6));
    }

    #[test]
    fn test_is_probably_prime() {
        assert!(BigNum::from_u64(2).is_probably_prime(5).unwrap());
        assert!(BigNum::from_u64(3).is_probably_prime(5).unwrap());
        assert!(BigNum::from_u64(5).is_probably_prime(5).unwrap());
        assert!(BigNum::from_u64(7).is_probably_prime(5).unwrap());
        assert!(!BigNum::from_u64(4).is_probably_prime(5).unwrap());
        assert!(!BigNum::from_u64(9).is_probably_prime(5).unwrap());
    }
}
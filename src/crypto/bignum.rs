// crypto/bignum.rs - Arbitrary-Precision Integer Implementation
// Provides basic arithmetic, modular operations, and primality testing for large integers.
// This uses a Vec<u64> to store the limbs of the big integer in little-endian order (least significant limb first)
// and implements various operations including addition, subtraction, multiplication, division, modular exponentiation,
// modular inverse, GCD, and Miller-Rabin primality testing.
// https://en.wikipedia.org/wiki/Arbitrary-precision_arithmetic

use crate::crypto::{Error, Result};
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Sub, Mul, Div, Rem, Shl, Shr, BitAnd, BitOr, BitXor};

// BigNum - Arbitrary-Precision Integer Implementation
#[derive(Clone, PartialEq, Eq)]
pub struct BigNum {
    pub limbs: Vec<u64>,
}

// MontgomeryContext - Precomputed values for Montgomery multiplication
#[derive(Clone)]
pub struct MontgomeryContext {
    modulus: BigNum,
    modulus_inv: u64,
    r2_mod_m: BigNum,
    bit_length: usize,
}

impl BigNum {

    /**
     * Create a BigNum from a u64 integer
     * Args:
     *    value - u64: The u64 integer to convert
     * 
     * Returns:
     *    Self: The corresponding BigNum instance
     */
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            BigNum { limbs: vec![0] }
        } else {
            BigNum { limbs: vec![value] }
        }
    }

    /**
     * Count the number of trailing zero bits in the BigNum
     * Args:
     *    n - &BigNum: The BigNum instance to analyze
     * 
     * Returns:
     *    usize: The number of trailing zero bits in the BigNum
     */
    pub fn trailing_zeros(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        
        let mut count = 0;
        for limb in self.limbs.iter() {
            if *limb == 0 {
                count += 64;
            } else {
                count += limb.trailing_zeros() as usize;
                break;
            }
        }

        count
    }

    /**
     * Create a BigNum from a big-endian byte slice
     * Args:
     *    bytes - &[u8]: The big-endian byte slice to convert
     * 
     * Returns:
     *    Self: The corresponding BigNum instance
     */
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

    /**
     * Create a BigNum from a little-endian byte slice
     * Args:
     *    bytes - &[u8]: The little-endian byte slice to convert
     * 
     * Returns:
     *    Self: The corresponding BigNum instance
     */
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

    /**
     * Create a BigNum from a vector of limbs (u64 values)
     * Args:
     *    mut limbs: Vec<u64> - The vector of limbs representing the big integer in little-endian order
     * 
     * Returns:
     *    Self: The corresponding BigNum instance with normalized limbs
     */
    pub fn from_limbs(mut limbs: Vec<u64>) -> Self {
        if limbs.is_empty() {
            return BigNum::zero();
        }

        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }

        BigNum { limbs }
    }

    /**
     * Convert the BigNum to a big-endian byte vector
     * Args:
     *    &self: The BigNum instance
     * 
     * Returns:
     *    Vec<u8>: The big-endian byte representation of the BigNum
     */
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

    /**
     * Convert the BigNum to a little-endian byte vector
     * Args:
     *    &self: The BigNum instance
     * 
     * Returns:
     *    Vec<u8>: The little-endian byte representation of the BigNum
     */
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

    /**
     * Create a BigNum representing zero
     * Args:
     *    (): Nothing
     * 
     * Returns:
     *    Self: BigNum instance set to 0
     */
    pub fn zero() -> Self {
        BigNum { limbs: vec![0] }
    }

    /**
     * Create a BigNum representing one
     * Args:
     *    (): Nothing
     * 
     * Returns:
     *    Self: BigNum instance set to 1
     */
    pub fn one() -> Self {
        BigNum { limbs: vec![1] }
    }

    /**
     * Check if the BigNum is zero
     * Args:
     *    &self: The BigNum instance
     * 
     * Returns:
     *    bool: true if BigNum is zero, false otherwise
     */
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&limb| limb == 0)
    }

    /**
     * Check if the BigNum is one
     * Args:
     *    &self: The BigNum instance
     * 
     * Returns:
     *    bool: true if BigNum is one, false otherwise
     */
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    /**
     * Check if the BigNum is even
     * Args:
     *    &self: The BigNum instance
     * 
     * Returns:
     *    bool: true if BigNum is even, false otherwise
     */
    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    /**
     * Check if the BigNum is odd
     * Args:
     *    &self: The BigNum instance
     * 
     * Returns:
     *    bool: true if BigNum is odd, false otherwise
     */
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }

    /**
     * Helper function to reduce a BigNum modulo m,
     * ensuring the result is less than m
     * Args:
     *    &self: The BigNum instance to reduce
     *    m - &BigNum: The modulus BigNum
     * 
     * Returns:
     *    BigNum: The result of self mod m being less than m
     */
    #[inline]
    fn mod_reduce(&self, m: &BigNum) -> BigNum {
        if self < m {
            self.clone()
        } else {
            self % m
        }
    }

    /**
     * Get the value of a specific bit in the BigNum (alt method that avoids indexing)
     * Args:
     *    &self: The BigNum instance
     *    pos - usize: The bit position to check
     * 
     * Returns:
     *    bool: true if the bit at position pos is set, false otherwise
     */
    #[inline]
    pub fn get_bit(&self, pos: usize) -> bool {
        let limb_index = pos / 64;
        let bit_in_limb = pos % 64;
        
        if limb_index >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_index] >> bit_in_limb) & 1 == 1
        }
    }

    /**
     * Get the total number of bits required to represent the BigNum 
     * (bit length)
     * Args:
     *    &self: The BigNum instance
     * 
     * Returns:
     *    usize: The bit length of the BigNum, which is the position of 
     *        the highest set bit + 1, or 0 if the BigNum is zero
     */
    #[inline]
    pub fn bit_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        
        let last_limb = self.limbs[self.limbs.len() - 1];
        let leading_zeros = last_limb.leading_zeros() as usize;
        64 * self.limbs.len() - leading_zeros
    }

    /**
     * Get the value of a specific bit in the BigNum
     * Args:
     *    &self: The BigNum instance
     *    pos - usize: The bit position to check
     * 
     * Returns:
     *    bool: true if the bit at position pos is set, false otherwise
     */
    pub fn bit(&self, pos: usize) -> bool {
        let limb_idx = pos / 64;
        let bit_idx = pos % 64;
        if limb_idx >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_idx] >> bit_idx) & 1 == 1
        }
    }

    /**
     * Set or clear a specific bit in the BigNum
     * Args:
     *    &mut self: The BigNum instance
     *    pos - usize: The bit position to set or clear
     *    value - bool: true to set the bit, false to clear it (1 or 0)
     * 
     * Returns:
     *    (): Nothing
     */
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

    /**
     * Modulo exponentiation: (self ^ exponent) mod modulus
     * This uses the method of exponentiation by squaring for efficiency, resulting in O(log(exponent) × M(n)) time complexity
     * Args:
     *    &self: The base BigNum
     *    exponent - &BigNum: The exponent BigNum used to raise the base
     *    modulus - &BigNum: The modulus BigNum to reduce the result
     * 
     * Returns:
     *    Result<BigNum>: The result of (self ^ exponent) mod modulus or an error if modulus is zero
     */
    #[deprecated(note = "Use mod_exp_montgomery for better performance with large moduli")]
    pub fn mod_exp(&self, exp: &BigNum, m: &BigNum) -> Result<BigNum> {
        if m.is_zero() {
            return Err(Error::CryptoError("Division by zero".to_string()));
        }

        let mut result = BigNum::one();
        let mut base = self.mod_reduce(m);
        let exponent = exp.clone();
        let bit_length = exponent.bit_length();
        for bit_idx in 0..bit_length {
            if exponent.get_bit(bit_idx) {
                result = (&result * &base).mod_reduce(m);
            }

            if bit_idx < bit_length - 1 {
                base = (&base * &base).mod_reduce(m);
            }
        }

        Ok(result)
    }

    /**
     * Modular exponentiation using Montgomery multiplication for improved performance with large moduli
     * Args:
     *    &self: The base BigNum
     *    exp - &BigNum: The exponent BigNum used to raise the base
     *    modulus - &BigNum: The modulus BigNum to reduce the result
     * 
     * Returns:
     *    Result<BigNum>: The result of (self ^ exp) mod modulus or an error if modulus is zero or not odd
     */
    pub fn mod_exp_montgomery(&self, exp: &BigNum, modulus: &BigNum) -> Result<BigNum> {
        let ctx = MontgomeryContext::new(modulus)?;
        
        let mut result = ctx.to_montgomery(&BigNum::one());
        let base_mont = ctx.to_montgomery(self);
        let bit_length = exp.bit_length();
        
        for i in (0..bit_length).rev() {
            result = ctx.multiply(&result, &result);
            if exp.get_bit(i) {
                result = ctx.multiply(&result, &base_mont);
            }
        }
        
        Ok(ctx.from_montgomery(&result))
    }

    /**
     * Modular inverse: Find x such that (self * x) mod modulus = 1
     * This uses the Extended Euclidean Algorithm (EEA) to compute the modular inverse
     * Args:
     *    &self: The BigNum instance for which to find the modular inverse
     *    modulus - &BigNum: The modulus BigNum
     * 
     * Returns:
     *    Result<BigNum>: The modular inverse of self mod modulus or an error if no inverse exists
     */
    pub fn mod_inverse(&self, modulus: &BigNum) -> Result<BigNum> {
        println!("mod_inverse called: self_bits={}, mod_bits={}", 
             self.bit_length(), modulus.bit_length());

        if self.is_zero() {
            return Err(Error::CryptoError("Cannot invert zero".to_string()));
        }
        if modulus.is_zero() {
            return Err(Error::CryptoError("Modulus cannot be zero".to_string()));
        }

        let mut r0 = modulus.clone();
        let mut r1 = self.clone() % modulus.clone();
        
        let mut s0 = BigNum::zero();
        let mut s1 = BigNum::one();
        let mut s0_neg = false;
        let mut s1_neg = false;

        while !r1.is_zero() {
            let (q, r2) = Self::div_rem_optimized(&r0, &r1);

            // s2 = s0 - q * s1
            let q_s1 = &q * &s1;
            let (s2, s2_neg) = signed_sub(&s0, s0_neg, &q_s1, s1_neg);

            r0 = r1;
            r1 = r2;
            s0 = s1;
            s0_neg = s1_neg;
            s1 = s2;
            s1_neg = s2_neg;
        }

        if !r0.is_one() {
            return Err(Error::CryptoError("No modular inverse exists".to_string()));
        }

        let result = if s0_neg {
            let s0_mod = &s0 % modulus;
            if s0_mod.is_zero() {
                BigNum::zero()
            } else {
                modulus - &s0_mod
            }
        } else {
            &s0 % modulus
        };

        Ok(result)
    }

    /**
     * Modulo operation that always returns a non-negative result
     * Args:
     *    &self: The BigNum instance
     *    modulus - &BigNum: The modulus BigNum
     * 
     * Returns:
     *    BigNum: The result of self mod modulus, guaranteed to be non-negative
     */
    pub fn modulo(&self, modulus: &BigNum) -> BigNum {
        self % modulus
    }

    /**
     * Compute the greatest common divisor (GCD) of two BigNums using the Euclidean algorithm
     * Args:
     *    &self: The first BigNum instance
     *    other - &BigNum: The second BigNum instance
     * 
     * Returns:
     *    BigNum: The GCD of self and other
     */
    pub fn gcd(&self, other: &BigNum) -> BigNum {
        let mut a = self.clone();
        let mut b = other.clone();
        while !b.is_zero() {
            let temp = b.clone();
            b = Self::div_rem_optimized(&a, &b).1;
            a = temp;
        }

        a
    }

    /**
     * Perform a probabilistic primality test using the Miller-Rabin algorithm
     * Args:
     *    &self: The BigNum instance to test for primality
     *    rounds - usize: The number of testing rounds to perform (higher means more accuracy)
     * 
     * Returns:
     *    Result<bool>: Ok(true) if probably prime, Ok(false) if composite, or an error if random generation fails
     */
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

        const SMALL_PRIMES: [u64; 30] = [
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
            37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
            79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        ];

        for &p in &SMALL_PRIMES {
            if self == &BigNum::from_u64(p) {
                return Ok(true);
            }
        }

        let n_minus_1 = self.clone() - BigNum::one();
        let n_minus_3 = self.clone() - BigNum::from_u64(3);
        let mut r = 0;
        let mut d = n_minus_1.clone();
        while d.is_even() {
            d = d >> 1;
            r += 1;
        }

        'witness: for _ in 0..rounds {
            let bytes_needed = (self.bit_length() + 7) / 8;
            let random_bytes = generate_random(bytes_needed)?;
            let mut a = BigNum::from_bytes_be(&random_bytes).modulo(&n_minus_3);
            a = a + BigNum::from_u64(2);

            let mut x = a.mod_exp_montgomery(&d, self)?;
            if x.is_one() || x == n_minus_1 {
                continue 'witness;
            }

            for _ in 0..(r - 1) {
                x = (&x * &x).modulo(self);
                if x == n_minus_1 {
                    continue 'witness;
                }
            }

            return Ok(false);
        }

        Ok(true)
    }

    /**
     * Generate a probable prime BigNum of specified bit length using the Miller-Rabin test
     * Args:
     *    bits - usize: The desired bit length of the prime
     *    rounds - usize: The number of Miller-Rabin rounds for primality testing
     * 
     * Returns:
     *    Result<BigNum>: A probable prime BigNum of the specified bit length
     */
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

    /**
     * EEA to compute GCD and coefficients x, y such that ax + by = gcd(a, b)
     * Args:
     *    a - &BigNum: The first BigNum
     *    b - &BigNum: The second BigNum
     * 
     * Returns:
     *    (BigNum, BigNum, BigNum): A tuple containing (gcd, x, y) satisfying the equation 
     */
    pub fn extended_gcd(a: &BigNum, b: &BigNum) -> (BigNum, BigNum, BigNum) {
        let mut r0 = a.clone();
        let mut r1 = b.clone();
        let mut s0 = BigNum::one();
        let mut s1 = BigNum::zero();
        let mut s0_neg = false;
        let mut s1_neg = false;

        while !r1.is_zero() {
            let (q, r2) = Self::div_rem_optimized(&r0, &r1);

            let q_s1 = &q * &s1;
            let (s2, s2_neg) = signed_sub(&s0, s0_neg, &q_s1, s1_neg);

            r0 = r1;
            r1 = r2;
            s0 = s1;
            s0_neg = s1_neg;
            s1 = s2;
            s1_neg = s2_neg;
        }

        (r0, s0, BigNum::zero())
    }

    /**
     * Normalize the BigNum by removing leading zero limbs
     * Args:
     *    &mut self: The BigNum instance
     * 
     * Returns:
     *    (): Nothing
     */
    fn normalize(&mut self) {
        while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /**
     * Compute the Montgomery constant R^2 mod m for a given modulus
     * Args:
     *    modulus - &BigNum: The modulus for which to compute the Montgomery constant
     * 
     * Returns:
     *    BigNum: The Montgomery constant R^2 mod m
     */
    fn compute_r_squared(modulus: &BigNum) -> BigNum {
        let k = modulus.limbs.len();
        let mut r_squared = BigNum::one();
        for _ in 0..(128 * k) {
            r_squared = (r_squared.clone() << 1) % modulus.clone();
        }

        r_squared
    }

    /**
     * Compute the Montgomery parameter m' such that m' * m = -1 (mod 2^64)
     * Args:
     *    modulus - &BigNum: The modulus for which to compute the Montgomery parameter
     * 
     * Returns:
     *    u64: The Montgomery parameter m'
     */
    fn compute_m_prime(modulus: &BigNum) -> u64 {
        let m = modulus.limbs[0];
        let mut x = m;
        for _ in 0..4 {
            x = x.wrapping_mul(2u64.wrapping_sub(m.wrapping_mul(x)));
        }

        x.wrapping_neg()
    }

    /**
     * Perform Montgomery multiplication of two numbers modulo a given modulus
     * Args:
     *    a - &[u64]: The first operand
     *    b - &[u64]: The second operand
     *    modulus - &[u64]: The modulus
     *    m_prime - u64: The Montgomery parameter
     * 
     * Returns:
     *    Vec<u64>: The result of the Montgomery multiplication
     */
    fn mont_mult(a: &[u64], b: &[u64], modulus: &[u64], m_prime: u64) -> Vec<u64> {
        let n = modulus.len();
        let mut t = vec![0u64; 2 * n + 1];
        for i in 0..n {
            let mut carry = 0u128;
            for j in 0..n {
                let product = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + carry;
                t[i + j] = product as u64;
                carry = product >> 64;
            }

            t[i + n] = carry as u64;
            let u = t[i].wrapping_mul(m_prime);
            carry = 0u128;
            for j in 0..n {
                let product = (u as u128) * (modulus[j] as u128) + (t[i + j] as u128) + carry;
                t[i + j] = product as u64;
                carry = product >> 64;
            }

            t[i + n] = (t[i + n] as u128 + carry) as u64;
        }

        let mut result: Vec<u64> = t[n..2 * n].to_vec();
        if Self::is_greater_or_equal(&result, modulus) {
            Self::sub_inplace(&mut result, modulus);
        }

        result
    }

    /**
     * Check if a is greater than or equal to b
     * Args:
     *    a - &[u64]: The first number
     *    b - &[u64]: The second number
     * 
     * Returns:
     *    bool: True if a is greater than or equal to b, false otherwise
     */
    fn is_greater_or_equal(a: &[u64], b: &[u64]) -> bool {
        if a.len() != b.len() {
            return a.len() > b.len();
        }

        for (x, y) in a.iter().zip(b.iter()).rev() {
            if x != y {
                return x > y;
            }
        }

        true
    }

    /**
     * Subtract b from a in place
     * Args:
     *    a - &mut [u64]: The number to subtract from
     *    b - &[u64]: The number to subtract
     * 
     * Returns:
     *    () - None
     */
    fn sub_inplace(a: &mut [u64], b: &[u64]) {
        let mut borrow = 0u64;
        for i in 0..a.len() {
            let b_val = b.get(i).copied().unwrap_or(0);
            let (diff1, underflow1) = a[i].overflowing_sub(b_val);
            let (diff2, underflow2) = diff1.overflowing_sub(borrow);
            a[i] = diff2;
            borrow = (underflow1 as u64) + (underflow2 as u64);
        }
    }

    /**
     * Wrapper function for Montgomery multiplication
     * Args:
     *    a - &BigNum: The first operand
     *    b - &BigNum: The second operand
     *    modulus - &BigNum: The modulus
     *    m_prime - u64: The Montgomery parameter
     * 
     * Returns:
     *    BigNum: The result of the Montgomery multiplication
     */
    fn mont_mult_wrapper(a: &BigNum, b: &BigNum, modulus: &BigNum, m_prime: u64) -> BigNum {
        let n = modulus.limbs.len();
        let mut a_limbs = a.limbs.clone();
        let mut b_limbs = b.limbs.clone();

        a_limbs.resize(n, 0);
        b_limbs.resize(n, 0);

        let result_limbs = Self::mont_mult(&a_limbs, &b_limbs, &modulus.limbs, m_prime);
        let mut result = BigNum { limbs: result_limbs };
        result.normalize();
        
        result
    }

    /**
     * Division with remainder using Knuth's algorithm D,
     * which is an optimized version of the standard long division algorithm
     * that reduces the number of expensive operations
     * Args:
     *    dividend - &BigNum: The number to be divided
     *    divisor - &BigNum: The number to divide by
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the quotient and remainder
     */
    fn div_rem_optimized(dividend: &BigNum, divisor: &BigNum) -> (BigNum, BigNum) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        if dividend < divisor {
            return (BigNum::zero(), dividend.clone());
        }

        if divisor.is_one() {
            return (dividend.clone(), BigNum::zero());
        }

        let divisor_limbs = divisor.limbs.len();
        let dividend_limbs = dividend.limbs.len();

        if divisor_limbs == 1 {
            return Self::div_rem_single_limb(dividend, divisor.limbs[0]);
        }

        if divisor_limbs <= 64 {
            return Self::div_rem_knuth(dividend, divisor);
        }

        Self::div_rem_burnikel_ziegler(dividend, divisor)
    }

    /**
     * Division with remainder when the divisor is a single limb (u64)
     * Args:
     *    dividend - &BigNum: The number to be divided
     *    divisor - u64: The single limb divisor
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the quotient and remainder as BigNum instances
     */
    fn div_rem_single_limb(dividend: &BigNum, divisor: u64) -> (BigNum, BigNum) {
        let mut quotient = Vec::new();
        let mut remainder = 0u128;
        for i in (0..dividend.limbs.len()).rev() {
            remainder = (remainder << 64) | (dividend.limbs[i] as u128);
            quotient.push((remainder / (divisor as u128)) as u64);
            remainder %= divisor as u128;
        }

        quotient.reverse();
        while quotient.len() > 1 && quotient[quotient.len() - 1] == 0 {
            quotient.pop();
        }

        if quotient.is_empty() {
            quotient.push(0);
        }

        (
            BigNum::from_limbs(quotient),
            BigNum::from_limbs(vec![remainder as u64]),
        )
    }

    /**
     * Division with remainder using Knuth's algorithm D
     * Args:
     *    dividend - &BigNum: The number to be divided
     *    divisor - &BigNum: The number to divide by
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the quotient and remainder as BigNums
     */
    fn div_rem_knuth(dividend: &BigNum, divisor: &BigNum) -> (BigNum, BigNum) {
        let shift = divisor.limbs.last().unwrap().leading_zeros() as usize;
        let v = if shift > 0 { divisor.clone() << shift } else { divisor.clone() };
        let mut u = if shift > 0 { dividend.clone() << shift } else { dividend.clone() };

        if u.limbs.len() < v.limbs.len() + 1 {
            u.limbs.push(0);
        }

        let n = v.limbs.len();
        let m = u.limbs.len() - n;
        let mut quotient = vec![0u64; m];

        for j in (0..m).rev() {
            let u_jn  = u.limbs.get(j + n).copied().unwrap_or(0) as u128;
            let u_jn1 = u.limbs.get(j + n - 1).copied().unwrap_or(0) as u128;
            let v_n1  = v.limbs[n - 1] as u128;
            let mut q_hat: u128 = if u_jn >= v_n1 {
                u64::MAX as u128
            } else {
                ((u_jn << 64) | u_jn1) / v_n1
            };

            loop {
                // Compute q_hat * v[j..j+n] - u[j..j+n+1]
                let mut sub_borrow: u128 = 0;
                let mut overshot = false;
                for i in 0..n {
                    let v_i = v.limbs[i] as u128;
                    let u_i = u.limbs.get(j + i).copied().unwrap_or(0) as u128;
                    let prod = q_hat * v_i + sub_borrow;
                    let prod_lo = prod & 0xFFFFFFFFFFFFFFFF;
                    sub_borrow = prod >> 64;
                    if u_i < prod_lo {
                        sub_borrow += 1;
                    }
                }

                let u_top = u.limbs.get(j + n).copied().unwrap_or(0) as u128;
                if sub_borrow > u_top {
                    overshot = true;
                }
                
                if !overshot {
                    break;
                }

                q_hat -= 1;
            }

            let mut borrow: u128 = 0;
            for i in 0..n {
                let v_i = v.limbs[i] as u128;
                let u_i = u.limbs.get(j + i).copied().unwrap_or(0) as u128;
                let prod = q_hat * v_i + borrow;
                let prod_lo = prod & 0xFFFFFFFFFFFFFFFF;
                borrow = prod >> 64;
                if u_i >= prod_lo {
                    if j + i < u.limbs.len() {
                        u.limbs[j + i] = (u_i - prod_lo) as u64;
                    }
                } else {
                    if j + i < u.limbs.len() {
                        u.limbs[j + i] = (u_i + (1u128 << 64) - prod_lo) as u64;
                    }

                    borrow += 1;
                }
            }

            if j + n < u.limbs.len() {
                u.limbs[j + n] = u.limbs[j + n].wrapping_sub(borrow as u64);
            }

            quotient[j] = q_hat as u64;
        }

        let mut remainder = BigNum::from_limbs(u.limbs[0..n].to_vec());
        if shift > 0 {
            remainder = remainder >> shift;
        }

        remainder.normalize();

        let mut q_bn = BigNum { limbs: quotient };
        q_bn.normalize();

        (q_bn, remainder)
    }

    /**
     * Division with remainder using the Burnikel-Ziegler algorithm
     * Args:
     *    dividend - &BigNum: The number to be divided
     *    divisor - &BigNum: The number to divide by
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the quotient and remainder as BigNums
     */
    fn div_rem_burnikel_ziegler(dividend: &BigNum, divisor: &BigNum) -> (BigNum, BigNum) {
        const BZ_THRESHOLD: usize = 64;
        if divisor.limbs.len() < BZ_THRESHOLD {
            return Self::div_rem_knuth(dividend, divisor);
        }

        Self::bz_divide_recursive(dividend, divisor)
    }

    /**
     * Division with remainder using the Burnikel-Ziegler algorithm
     * Args:
     *    a - &BigNum: The number to be divided
     *    b - &BigNum: The number to divide by
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the quotient and remainder as BigNums
     */
    #[deprecated(note = "Use bz_divide_recursive for better performance with large divisors")]
    fn bz_divide(a: &BigNum, b: &BigNum) -> (BigNum, BigNum) {
        const BZ_THRESHOLD: usize = 64;
        if b.limbs.len() < BZ_THRESHOLD {
            return Self::div_rem_knuth(a, b);
        }

        let n = b.limbs.len();
        let m = a.limbs.len() - n;

        let shift = b.limbs[n - 1].leading_zeros() as usize;
        
        let a_normalized = if shift > 0 {
            a.clone() << shift
        } else {
            a.clone()
        };
        
        let b_normalized = if shift > 0 {
            b.clone() << shift
        } else {
            b.clone()
        };

        let b_half = (n + 1) / 2;
        
        let (b1, b0) = Self::bz_split(&b_normalized, b_half);
        let (a1, a0) = Self::bz_split(&a_normalized, b_half);
        let a_high: BigNum = if a1.is_zero() {
            a_normalized.clone()
        } else {
            a1.clone()
        };

        let (mut q, mut r) = Self::bz_divide_step(&a_high, &b1);
        let r_shifted = if b_half > 0 {
            &r << (b_half * 64)
        } else {
            r.clone()
        };
        
        let mut a_remainder = &r_shifted + &a0;
        let q_refined = Self::bz_refine_quotient(&mut a_remainder, &b_normalized, &q, b_half);
        let remainder = if shift > 0 {
            a_remainder >> shift
        } else {
            a_remainder
        };

        let mut remainder_final = remainder;
        remainder_final.normalize();
        
        let mut q_final = q_refined;
        q_final.normalize();

        (q_final, remainder_final)
    }

    /**
     * Helper function to split a BigNum into high and low parts based on a specified bit position
     * Args:
     *    a - &BigNum: The BigNum to split
     *    pos - usize: The bit position to split at (number of bits in the low part)
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the high and low parts of the BigNum as BigNums
     */
    fn bz_split(a: &BigNum, pos: usize) -> (BigNum, BigNum) {
        let pos_bits = pos * 64;
        let low = if pos >= a.limbs.len() {
            a.clone()
        } else {
            BigNum::from_limbs(a.limbs[0..pos].to_vec())
        };

        let high = if pos >= a.limbs.len() {
            BigNum::zero()
        } else {
            BigNum::from_limbs(a.limbs[pos..].to_vec())
        };

        (high, low)
    }

    /**
     * Perform one step of the Burnikel-Ziegler division algorithm
     * Args:
     *    a - &BigNum: The number to be divided
     *    b - &BigNum: The number to divide by
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the quotient and remainder as BigNums
     */
    fn bz_divide_step(a: &BigNum, b: &BigNum) -> (BigNum, BigNum) {
        if b.is_zero() {
            panic!("Division by zero in BZ algorithm");
        }

        if a < b {
            return (BigNum::zero(), a.clone());
        }

        if b.limbs.len() <= 2 {
            return Self::div_rem_single_limb(a, b.limbs[0]);
        }

        Self::div_rem_knuth(a, b)
    }

    /**
     * Refine the quotient estimate in the Burnikel-Ziegler algorithm by performing extra subtraction steps
     * Args:
     *    remainder - &mut BigNum: The current remainder that may be greater than or equal to the divisor
     *    divisor - &BigNum: The divisor used in the division
     *    quotient - &BigNum: The current quotient estimate that may need to be incremented
     *    b_half - usize: The bit position used for splitting in the BZ algorithm
     * 
     * Returns:
     *    BigNum: The refined quotient after adjusting for any remaining excess in the remainder
     */
    fn bz_refine_quotient(remainder: &mut BigNum, divisor: &BigNum, quotient: &BigNum, b_half: usize) -> BigNum {
        let mut q = quotient.clone();
        while (&*remainder) >= divisor {
            *remainder = remainder.clone() - divisor;
            q = &q + &BigNum::one();
        }

        if remainder.is_zero() || (&*remainder) < divisor {
            q
        } else {
            q
        }
    }

    /**
     * Recursive division using Monagan's version of the Burnikel-Ziegler algorithm
     * Args:
     *    a - &BigNum: The number to be divided
     *    b - &BigNum: The number to divide by
     * 
     * Returns:
     *    (BigNum, BigNum): A tuple containing the quotient and remainder as BigNums
     */
    fn bz_divide_recursive(a: &BigNum, b: &BigNum) -> (BigNum, BigNum) {
        if b.limbs.len() < 64 {
            return Self::div_rem_knuth(a, b);
        }

        let n = b.limbs.len();
        let m = a.limbs.len();
        if m < n {
            return (BigNum::zero(), a.clone());
        }

        let shift = b.limbs[n - 1].leading_zeros() as usize;
        let a_norm = if shift > 0 { a.clone() << shift } else { a.clone() };
        let b_norm = if shift > 0 { b.clone() << shift } else { b.clone() };
        let k = (n + 1) / 2;
        let b1 = BigNum::from_limbs(
            b_norm.limbs.iter().skip(k).cloned().collect()
        );

        let b0 = BigNum::from_limbs(
            b_norm.limbs.iter().take(k).cloned().collect()
        );

        let mut a_parts = vec![BigNum::zero(); 3];
        if m >= 2 * k {
            a_parts[2] = BigNum::from_limbs(
                a_norm.limbs.iter().skip(2 * k).cloned().collect()
            );

            a_parts[1] = BigNum::from_limbs(
                a_norm.limbs.iter().skip(k).take(k).cloned().collect()
            );

            a_parts[0] = BigNum::from_limbs(
                a_norm.limbs.iter().take(k).cloned().collect()
            );
        } else if m >= k {
            a_parts[1] = BigNum::from_limbs(
                a_norm.limbs.iter().skip(k).cloned().collect()
            );

            a_parts[0] = BigNum::from_limbs(
                a_norm.limbs.iter().take(k).cloned().collect()
            );
        } else {
            a_parts[0] = a_norm.clone();
        }

        let a2 = a_parts[2].clone();
        let a1 = a_parts[1].clone();
        let a0 = a_parts[0].clone();
        let a_high = if a2.is_zero() {
            a1.clone()
        } else {
            let a2_shifted = &a2 << (k * 64);
            &a2_shifted + &a1
        };

        let (q1, r1) = Self::bz_divide_recursive(&a_high, &b1);
        let r1_shifted = &r1 << (k * 64);
        let rem1 = &r1_shifted + &a0;

        let (q0, r0) = Self::bz_divide_recursive(&rem1, &b_norm);

        let q_high = &q1 << (k * 64);
        let q_final = &q_high + &q0;
        let remainder_final = if shift > 0 {
            r0 >> shift
        } else {
            r0
        };

        let mut q_out = q_final;
        let mut r_out = remainder_final;
        q_out.normalize();
        r_out.normalize();

        (q_out, r_out)
    }
}

impl MontgomeryContext {

    /**
     * Create a new MontgomeryContext for a given modulus
     * Args:
     *    modulus - &BigNum: The modulus for which to create the Montgomery context (must be odd)
     * 
     * Returns:
     *    Result<Self>: A new MontgomeryContext instance or an error if the modulus is invalid
     */
    pub fn new(modulus: &BigNum) -> Result<Self> {
        if modulus.is_even() {
            return Err(Error::CryptoError("Modulus must be odd for Montgomery multiplication".to_string()));
        }

        let bit_length = modulus.bit_length();
        let modulus_inv = Self::compute_modulus_inv(&modulus.limbs[0]);        
        let k = modulus.limbs.len();
        let r = BigNum::from_limbs(vec![0u64; k + 1]);
        let r_squared = BigNum::compute_r_squared(modulus);
        let r2_mod_m = &r_squared % modulus;

        Ok(MontgomeryContext {
            modulus: modulus.clone(),
            modulus_inv,
            r2_mod_m,
            bit_length,
        })
    }

    /**
     * Compute the modular inverse of the modulus for Montgomery multiplication
     * Args:
     *    m - &u64: The least significant limb of the modulus (must be odd)
     * 
     * Returns:
     *    u64: The modular inverse of m modulo 2^64
     */
    fn compute_modulus_inv(m: &u64) -> u64 {
        let mut x = m.wrapping_mul(m.wrapping_sub(2));
        x = x.wrapping_mul(2u64.wrapping_sub(m.wrapping_mul(x)));
        x = x.wrapping_mul(2u64.wrapping_sub(m.wrapping_mul(x)));
        x = x.wrapping_mul(2u64.wrapping_sub(m.wrapping_mul(x)));
        x = x.wrapping_mul(2u64.wrapping_sub(m.wrapping_mul(x)));
        x.wrapping_neg()
    }

    /**
     * Reduce a BigNum t modulo the Montgomery modulus using the Montgomery reduction algorithm
     * Args:
     *    &self: The MontgomeryContext instance
     *    t - &BigNum: The BigNum to be reduced (should be less than modulus * R)
     * 
     * Returns:
     *    BigNum: The result of t reduced modulo the Montgomery modulus
     */
    pub fn reduce(&self, t: &BigNum) -> BigNum {
        let k = self.modulus.limbs.len();
        let mut r = vec![0u64; 2 * k + 1];
        
        for (i, &limb) in t.limbs.iter().enumerate() {
            if i < r.len() {
                r[i] = limb;
            }
        }
        
        for i in 0..k {
            let q = r[i].wrapping_mul(self.modulus_inv);
            let mut carry: u128 = 0;
            
            for j in 0..k {
                let prod = (q as u128) * (self.modulus.limbs[j] as u128)
                    + (r[i + j] as u128)
                    + carry;
                r[i + j] = prod as u64;
                carry = prod >> 64;
            }
            
            let mut pos = i + k;
            loop {
                let sum = (r[pos] as u128) + carry;
                r[pos] = sum as u64;
                carry = sum >> 64;
                if carry == 0 || pos + 1 >= r.len() {
                    break;
                }
                pos += 1;
            }
        }
        
        let mut result = BigNum::from_limbs(r[k..].to_vec());
        result.normalize();
        
        if result >= self.modulus {
            result = &result - &self.modulus;
        }
        
        result
    }

    /**
     * Perform Montgomery multiplication of two BigNums
     * Args:
     *    &self: The MontgomeryContext instance
     *    a - &BigNum: The first operand in Montgomery form
     *    b - &BigNum: The second operand in Montgomery form
     * 
     * Returns:
     *    BigNum: The result of the Montgomery multiplication
     */
    pub fn multiply(&self, a: &BigNum, b:&BigNum) -> BigNum {
        let n = self.modulus.limbs.len();
        let mut a_limbs = a.limbs.clone();
        let mut b_limbs = b.limbs.clone();
        a_limbs.resize(n, 0);
        b_limbs.resize(n, 0);
        let mut t = vec![0u64; 2 * n + 1];

        for i in 0..n {
            let mut carry: u128 = 0;
            for j in 0..n {
                let prod = (a_limbs[i] as u128) * (b_limbs[j] as u128)
                    + (t[i + j] as u128)
                    + carry;
                t[i + j] = prod as u64;
                carry = prod >> 64;
            }

            t[i + n] = (t[i + n] as u128 + carry) as u64;

            let q = t[i].wrapping_mul(self.modulus_inv);
            carry = 0;
            for j in 0..n {
                let prod = (q as u128) * (self.modulus.limbs[j] as u128)
                    + (t[i + j] as u128)
                    + carry;
                t[i + j] = prod as u64;
                carry = prod >> 64;
            }

            t[i + n] = (t[i + n] as u128 + carry) as u64;
        }

        let mut result = BigNum::from_limbs(t[n..2 * n].to_vec());
        result.normalize();
        if result >= self.modulus {
            result = &result - &self.modulus;
        }

        result
    }

    /**
     * Convert a BigNum to Montgomery form
     * Args:
     *    &self: The MontgomeryContext instance
     *    a - &BigNum: The BigNum to convert to Montgomery form
     * 
     * Returns:
     *    BigNum: The Montgomery form of the input BigNum
     */
    pub fn to_montgomery(&self, a: &BigNum) -> BigNum {
        self.multiply(a, &self.r2_mod_m)
    }

    /**
     * Convert a BigNum from Montgomery form back to regular form
     * Args:
     *    &self: The MontgomeryContext instance
     *    a_mont - &BigNum: The BigNum in Montgomery form to convert
     * 
     * Returns:
     *    BigNum: The regular form of the input BigNum
     */
    pub fn from_montgomery(&self, a_mont: &BigNum) -> BigNum {
        self.multiply(a_mont, &BigNum::one())
    }
}

// Debug implementation for BigNum
impl fmt::Debug for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BigNum(0x{})", hex::encode(&self.to_bytes_be()))
    }
}

// Display implementation for BigNum
impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes_be()))
    }
}

// PartialOrd implementation for BigNum
impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Ord implementation for BigNum
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

// Addition implementation for BigNum
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

// Addition for right BigNum reference and owned BigNum
impl Add<&BigNum> for BigNum {
    type Output = BigNum;
    fn add(self, other: &BigNum) -> BigNum {
        self + other.clone()
    }
}

// Addition for BigNum references
impl<'a, 'b> Add<&'b BigNum> for &'a BigNum {
    type Output = BigNum;
    fn add(self, other: &'b BigNum) -> BigNum {
        self.clone().add(other.clone())
    }
}

// Addition for left BigNum reference and owned BigNum
impl<'a> Add<BigNum> for &'a BigNum {
    type Output = BigNum;
    fn add(self, other: BigNum) -> BigNum {
        self.clone().add(other)
    }
}

// Subtraction implementation for BigNum
impl Sub for BigNum {
    type Output = BigNum;
    fn sub(self, other: BigNum) -> BigNum {
        if self < other {
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

// Subtraction for right BigNum reference and owned BigNum
impl Sub<&BigNum> for BigNum {
    type Output = BigNum;
    fn sub(self, other: &BigNum) -> BigNum {
        self - other.clone()
    }
}

// Subtraction for BigNum references
impl<'a, 'b> Sub<&'b BigNum> for &'a BigNum {
    type Output = BigNum;

    fn sub(self, other: &'b BigNum) -> BigNum {
        self.clone().sub(other.clone())
    }
}

// Subtraction for left BigNum reference and owned BigNum
impl<'a> Sub<BigNum> for &'a BigNum {
    type Output = BigNum;

    fn sub(self, other: BigNum) -> BigNum {
        self.clone().sub(other)
    }
}


// Multiplication implementation for BigNum
impl Mul for BigNum {
    type Output = BigNum;
    fn mul(self, rhs: BigNum) -> BigNum {
        (&self) * (&rhs)
    }
}

// Multiplication for right BigNum reference and owned BigNum
impl Mul<&BigNum> for BigNum {
    type Output = BigNum;
    fn mul(self, other: &BigNum) -> BigNum {
        (&self) * other
    }
}

// Multiplication for BigNum references
impl<'a, 'b> Mul<&'b BigNum> for &'a BigNum {
    type Output = BigNum;
    fn mul(self, rhs: &'b BigNum) -> BigNum {
        let mut result = vec![0u64; self.limbs.len() + rhs.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            if a == 0 {
                continue;
            }
            
            let mut carry = 0u128;
            for (j, &b) in rhs.limbs.iter().enumerate() {
                let prod = (a as u128) * (b as u128) + (result[i + j] as u128) + carry;
                result[i + j] = prod as u64;
                carry = prod >> 64;
            }
            
            if carry > 0 {
                result[i + rhs.limbs.len()] = carry as u64;
            }
        }
        
        BigNum::from_limbs(result)
    }
}

// Multiplication for left BigNum reference and owned BigNum
impl<'a> Mul<BigNum> for &'a BigNum {
    type Output = BigNum;
    fn mul(self, rhs: BigNum) -> BigNum {
        self * (&rhs)
    }
}

// Division implementation for BigNum
impl Div for BigNum {
    type Output = BigNum;
    fn div(self, other: BigNum) -> BigNum {
        self.div_rem(&other).0
    }
}

// Division for BigNum references
impl<'a, 'b> Div<&'b BigNum> for &'a BigNum {
    type Output = BigNum;
    fn div(self, other: &'b BigNum) -> BigNum {
        self.clone().div(other.clone())
    }
}

// Division for left BigNum reference and owned BigNum
impl<'a> Div<BigNum> for &'a BigNum {
    type Output = BigNum;

    fn div(self, other: BigNum) -> BigNum {
        self.clone().div(other)
    }
}

// Remainder implementation for BigNum
impl Rem for BigNum {
    type Output = BigNum;
    fn rem(self, other: BigNum) -> BigNum {
        self.div_rem(&other).1
    }
}

// Remainder for BigNum references
impl<'a, 'b> Rem<&'b BigNum> for &'a BigNum {
    type Output = BigNum;
    fn rem(self, other: &'b BigNum) -> BigNum {
        self.clone().rem(other.clone())
    }
}

// Remainder for left BigNum reference and owned BigNum
impl<'a> Rem<BigNum> for &'a BigNum {
    type Output = BigNum;
    fn rem(self, other: BigNum) -> BigNum {
        self.clone().rem(other)
    }
}

// Division with remainder implementation for BigNum
impl BigNum {

    // Division with remainder
    fn div_rem(&self, divisor: &BigNum) -> (BigNum, BigNum) {
        Self::div_rem_optimized(self, divisor)
    }
}

// Left shift implementation for BigNum
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

// Left shift for BigNum references
impl<'a> Shl<usize> for &'a BigNum {
    type Output = BigNum;
    fn shl(self, shift: usize) -> BigNum {
        self.clone() << shift
    }
}

// Right shift implementation for BigNum
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

// Right shift for BigNum references
impl<'a> Shr<usize> for &'a BigNum {
    type Output = BigNum;
    fn shr(self, shift: usize) -> BigNum {
        self.clone() >> shift
    }
}

// Bitwise AND implementation for BigNum
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

// Bitwise OR implementation for BigNum
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

// Bitwise XOR implementation for BigNum
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

/**
 * Helper function to count the number of trailing zero bits in a BigNum
 * (Find the highest power of 2 that divides n)
 * Args:
 *    n - &BigNum: The BigNum to analyze
 * 
 * Returns:
 *    usize: The number of trailing zero bits in n
 */
fn trailing_zeros(n: &BigNum) -> usize {
    if n.is_zero() {
        return 0;
    }
    
    let mut count = 0;
    for limb in n.limbs.iter() {
        if *limb == 0 {
            count += 64;
        } else {
            count += limb.trailing_zeros() as usize;
            break;
        }
    }
    count
}

fn signed_sub(a: &BigNum, a_neg: bool, b: &BigNum, b_neg: bool) -> (BigNum, bool) {
    if a_neg == b_neg {
        if a >= b {
            (a - b, a_neg)
        } else {
            (b - a, !a_neg)
        }
    } else {
        (a + b, a_neg)
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
        let result = base.mod_exp_montgomery(&exp, &modulus).unwrap();
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
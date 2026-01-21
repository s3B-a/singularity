use std::sync::Mutex;
use crate::crypto::{Error, Result};

static GLOBAL_RNG: Mutex<Option<SystemRng>> = Mutex::new(None);

pub trait CryptoRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()>;

    fn generate_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];
        self.fill_bytes(&mut buffer)?;
        Ok(buffer)
    }

    fn generate_u32(&mut self) -> Result<u32> {
        let mut buffer = [0u8; 4];
        self.fill_bytes(&mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }
    
    fn generate_u64(&mut self) -> Result<u64> {
        let mut buffer = [0u8; 8];
        self.fill_bytes(&mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }
}

pub struct SystemRng {
    #[cfg(target_os = "windows")]
    _phantom: std::marker::PhantomData<()>,
}

impl SystemRng {
    pub fn new() -> Result<Self> {
        Ok(SystemRng {
            #[cfg(target_os = "windows")]
            _phantom: std::marker::PhantomData,
        })
    }
}

impl Default for SystemRng {
    fn default() -> Self {
        Self::new().expect("Failed to initialize system RNG")
    }
}

impl CryptoRng for SystemRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        sys_fill_bytes(dest)
    }
}

// Windows Implementation
// Use BCryptGenRandom from bcrypt.dll
#[cfg(target_os = "windows")]
fn sys_fill_bytes(dest: &mut [u8]) -> Result<()> {
    use std::ptr;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            hAlgoreithm: *mut std::ffi::c_void,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYS_PREFERRED_RNG: u32 = 0x00000002;
    const STATUS_SUCCESS: i32 = 0;
    let result = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            dest.as_mut_ptr(),
            dest.len() as u32,
            BCRYPT_USE_SYS_PREFERRED_RNG,
        )
    };

    if result == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(Error::InsufficientEntropy)
    }
}

// Unix Implementation (Linux, BSD, Android, etc.)
// use getrandom syscall or /dev/urandom
#[cfg(all(unix, not(target_os = "macos"), not(target_os = "ios")))]
fn sys_fill_bytes(dest: &mut [u8]) -> Result<()> {
    // getrandom syscall first (Linux 3.17+ / Modern BSDs)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        #[cfg(target_pointer_width = "64")]
        type CLong = i64;
        #[cfg(target_pointer_width = "32")]
        type CLong = i32;

        unsafe extern "C" {
            fn syscall(num: CLong, ...) -> CLong;
        }

        #[cfg(target_arch = "x86_64")]
        const SYS_GETRANDOM: CLong = 318;
        #[cfg(target_arch = "x86")]
        const SYS_GETRANDOM: CLong = 355;
        #[cfg(target_arch = "aarch64")]
        const SYS_GETRANDOM: CLong = 278;
        #[cfg(target_arch = "arm")]
        const SYS_GETRANDOM: CLong = 384;
        #[cfg(target_arch = "riscv64")]
        const SYS_GETRANDOM: CLong = 278;
        #[cfg(target_arch = "s390x")]
        const SYS_GETRANDOM: CLong = 349;

        let mut filled = 0;
        while filled < dest.len() {
            let ret = unsafe {
                syscall(
                    SYS_GETRANDOM,
                    dest[filled..].as_mut_ptr(),
                    dest.len() - filled,
                    0,
                )
            };

            if ret > 0 {
                filled += ret as usize;
            } else if ret == -1 {
                return read_urandom(dest);
            }
        }

        return Ok(());
    }

    read_urandom(dest) // fallback
}

// Helper read from /dev/urandom
#[cfg(unix)]
fn read_urandom(dest: &mut [u8]) -> Result<()> {
    use std::fs::File;
    use std::io::Read;
    let mut file = File::open("/dev/urandom").map_err(|_| Error::InsufficientEntropy)?;
    file.read_exact(dest).map_err(|_| Error::InsufficientEntropy)?;

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn sys_fill_bytes(dest: &mut [u8]) -> Result<()> {
    Err(Error::CryptoError(
        "I am computist against darwin-based machines, run linux or something.".to_string(),
    ))
}

#[cfg(target_arch = "wasm32")]
fn sys_fill_bytes(dest: &mut [u8]) -> Result<()> {
    Err(Error::CryptoError(
        "WASM requires external JS crypto API integration, the module will be implemented later.".to_string(),
    ))
}

#[cfg(not(any(target_os = "windows", unix, target_arch = "wasm32")))]
fn sys_fill_bytes(dest: &[u8]) -> Result<()> {
    compile_error!("Unsupported platform for cryptographic RNG");
}

pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    let mut rng_guard = GLOBAL_RNG.lock().unwrap();
    if rng_guard.is_none() {
        *rng_guard = Some(SystemRng::new()?);
    }

    rng_guard.as_mut().unwrap().fill_bytes(dest)
}

pub fn generate_random(len: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    fill_random(&mut buffer)?;

    Ok(buffer)
}

pub fn generate_random_u32() -> Result<u32> {
    let mut buffer = [0u8; 4];
    fill_random(&mut buffer)?;

    Ok(u32::from_le_bytes(buffer))
}

pub fn generate_random_u64() -> Result<u64> {
    let mut buffer = [0u8; 8];
    fill_random(&mut buffer)?;
    
    Ok(u64::from_le_bytes(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random() {
        let mut buf = [0u8; 32];
        fill_random(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }
}
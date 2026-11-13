# Singularity Standards
## Rust File Layout
Every `.rs` file in Singularity orders its top-level items the same way so items/sections can be found easily when reading the code. This file serves as a way for future maintainers to understand the current (11/13/2026) formatting standards for Singularity

### Order (top/down)

1. **File header comment**: describes the file and stays at the very top
2. **`macro_rules!`**
3. **`mod` declarations**: `mod x;` / `pub mod x;`
4. **Imports**
   1. `pub use` re-exports
   2. `use crate::...`, followed directly by `use super::...` (no blank line between them)
   3. `use std::...`
5. **Constants, statics and types**: `pub const`, `const`, `pub static`, `static` (including `thread_local!`), `pub type`, `type`
6. **Type definitions**: `pub struct`, `struct`, `pub enum`, `enum`, `pub trait`, `trait`, `pub union`, `union`
7. **Implementations**
   1. Inherent impls: `impl Type { ... }`
   2. Trait impls: `impl Trait for Type { ... }` (ex. `impl fmt::Display for DnsRecord`)
8. **Functions**
   1. `pub fn`
   2. `fn`
   3. `#[inline]` / `#[cold]` functions
   4. `pub(crate)` functions
9. **Inline modules**: `mod hex { ... }`, `pub mod oid { ... }`
10. **Tests**: `#[cfg(test)] mod tests { ... }` (or `#[cfg(test)] mod tests;`)

### Comments
- Although not currently implemented, comments such as doc strings will be formatted as shown within the example, containing information on what the function does, the arguments it takes and what it returns
- With arguments/returns:
    1. Include the name of the variable along with what it's type is (ex. `f - &mut fmt::Formatter`)
    2. If a self exists, ensure that it's specified (ex. `&self: The current instance`)
    3. If there are no values for either args or returns, simply format it as `() - None`
    4. Arguments and returns should be 5 spaces from the astrisk line (ex. `*_____Argument - string: example argument`)

### Blank lines

- Put one blank line between groups
- Single-line items in the same group (imports, constants) may be stacked without blank lines
- Separate multi-line items (structs, impls, functions) with one blank line

### Scope

These rules apply to top-level items only. Anything inside an `impl`, function or inline module isn't required to be formatted

### Example

```rust
// net/example.rs - Short description of the file
// That can be multiple lines if needed

use crate::net::http::Headers;
use super::error::Result;

use std::fmt;

pub const MAX_SIZE: usize = 1024;
const MAGIC: &str = "EXAMPLE";

// Short explanation of the Example struct
pub struct Example {
    size: usize,
}

impl Example {

    /**
     * Explanation of the new function
     * Args:
     *     () - None
     * 
     * Returns:
     *     Self: The example instance
     */
    pub fn new() -> Self {
        Self { size: 0 }
    }
}

impl fmt::Display for Example {

    /**
     * Explanation of the function
     * Args:
     *     &self: The Example instance
     *     f - &mut fmt::Formatter: The formatter instance
     * 
     * Returns:
     *     fmt::Result: The formatting result
     */
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.size)
    }
}

/**
 * Explanation of the build function
 * Args:
 *     () - None
 * 
 * Returns:
 *     Example: The new Example instance
 */
pub fn build() -> Example {
    Example::new()
}

/**
 * Explanation of the helper function
 * Args:
 *     () - None
 * 
 * Returns:
 *     () - None
 */
fn helper() {}

/**
 * Explanation of the fast_helper function
 * Args:
 *     () - None
 * 
 * Returns:
 *     () - None
 */
#[inline]
fn fast_helper() {}

/**
 * Explanation of the internal function
 * Args:
 *     () - None
 * 
 * Returns:
 *     () - None
 */
pub(crate) fn internal() {}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
```
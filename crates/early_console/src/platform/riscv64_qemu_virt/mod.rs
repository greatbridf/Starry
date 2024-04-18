pub mod time;

/// Writes a byte to the console.
pub fn putchar(c: u8) {
    #[allow(deprecated)]
    sbi_rt::legacy::console_putchar(c as usize);
}

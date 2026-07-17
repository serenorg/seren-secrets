pub(crate) fn fill_random(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("operating system randomness is unavailable");
}

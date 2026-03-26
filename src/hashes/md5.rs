pub fn crack(word: &str) -> String {
    format!("{:x}", md5::compute(word))
}

use crate::reporter::Reporter;

pub trait CrackingBackend {
    fn run(
        &self,
        hashes: &[&str],
        wordlist: &str,
        hash_type: &str,
        rule: bool,
        reporter: &Reporter,
    ) -> usize;
}

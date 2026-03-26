pub fn apply(word: &str) -> Vec<String> {
    let mut variants = vec![word.to_string()];

    // first letter capitalized example = Password
    let mut capitalize = word.to_string();
    if let Some(first) = capitalize.get_mut(..1) {
        first.make_ascii_uppercase()
    }

    variants.push(capitalize);

    // Full upercase
    variants.push(word.to_uppercase());

    // reversed
    variants.push(word.chars().rev().collect());

    // adds numbers at the end
    variants.push(format!("{}1", word));
    variants.push(format!("{}123", word));

    //symbols
    variants.push(format!("{}!", word));
    variants.push(format!("{}@", word));

    //append year
    variants.push(format!("{}2026", word));
    variants.push(format!("{}2025", word));
    variants.push(format!("{}2024", word));
    variants.push(format!("{}2023", word));
    variants.push(format!("{}2022", word));

    let leet: String = word
        .chars()
        .map(|c| match c {
            'a' => '@',
            'e' => '3',
            'o' => '0',
            's' => '$',
            'i' => '1',
            _ => c,
        })
        .collect();
    variants.push(leet);

    variants
}

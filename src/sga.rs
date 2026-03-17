use crate::error::ValidationErrors;

const SGA_TABLE: [(char, &str); 26] = [
    ('a', "ᔑ"),
    ('b', "ʖ"),
    ('c', "ϟ"),
    ('d', "ᓵ"),
    ('e', "↸"),
    ('f', "ᒷ"),
    ('g', "⋑"),
    ('h', "⊣"),
    ('i', "∷"),
    ('j', "↻"),
    ('k', "ꖌ"),
    ('l', "ꖎ"),
    ('m', "ᒲ"),
    ('n', "リ"),
    ('o', "𝙹"),
    ('p', "⎓"),
    ('q', "ᑑ"),
    ('r', "∴"),
    ('s', "ꓤ"),
    ('t', "ʇ"),
    ('u', "⚍"),
    ('v', "⍊"),
    ('w', "∺"),
    ('x', "⊐"),
    ('y', "⋮"),
    ('z', "ꖙ"),
];

pub fn encode(text: &str) -> String {
    text.chars()
        .map(|c| {
            let lower = c.to_ascii_lowercase();
            match SGA_TABLE.iter().find(|(latin, _)| *latin == lower) {
                Some((_, char)) => char.to_string(),
                None => c.to_string(),
            }
        })
        .collect::<String>()
}

pub fn decode(text: &str) -> Result<String, ValidationErrors> {
    if text.is_empty() {
        return Err(ValidationErrors::EmptyCharacters);
    }

    Ok(text
        .chars()
        .map(|s| {
            match SGA_TABLE
                .iter()
                .find(|(_, symbol)| *symbol == s.to_string().as_str())
            {
                Some((latin, _)) => latin.to_string(),
                None => s.to_string(),
            }
        })
        .collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_to_correct_char() {
        assert_eq!(encode("a"), "ᔑ");
    }

    #[test]
    fn non_encode_to_same_string() {
        assert_ne!(encode("hi"), "hi");
    }

    #[test]
    fn encode_preserves_additional_char() {
        let result = encode("Hello World 123");
        assert!(result.contains(' '));
        assert!(result.contains('1'));
    }

    #[test]
    fn decode_to_correct_symbol() {
        assert_eq!(decode("ᔑ").unwrap(), "a")
    }

    #[test]
    fn non_decode_to_same_string() {
        assert_ne!(decode("ʖᔑʖᔑ").unwrap(), "ʖᔑʖᔑ");
    }

    #[test]
    fn decode_preserves_whole_string() {
        let phrase: String = "hello world".to_string();

        let encode_result = encode(&phrase);

        assert_eq!(decode(&encode_result).unwrap(), phrase);
    }
}

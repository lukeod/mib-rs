use crate::types::Language;

pub(super) fn language_rank(lang: Language) -> u8 {
    match lang {
        Language::SMIv2 => 2,
        Language::SMIv1 => 1,
        Language::Unknown => 0,
    }
}

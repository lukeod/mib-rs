use super::ByteOffset;

/// Scans source bytes and returns a table mapping line numbers to byte offsets.
/// Entry i is the byte offset where line i+1 starts. Line 1 always starts at offset 0.
pub fn build_line_table(source: &[u8]) -> Vec<usize> {
    let n = 1 + source.iter().filter(|&&b| b == b'\n').count();
    let mut table = Vec::with_capacity(n);
    table.push(0);
    for (i, &b) in source.iter().enumerate() {
        if b == b'\n' {
            table.push(i + 1);
        }
    }
    table
}

/// Converts a byte offset to 1-based line and column numbers using a precomputed
/// line table. Returns (0, 0) if the table is empty or the offset is synthetic.
pub fn line_col_from_table(table: &[usize], offset: ByteOffset) -> (usize, usize) {
    if table.is_empty() || offset == ByteOffset::SYNTHETIC {
        return (0, 0);
    }
    let off = offset.0 as usize;
    let line_idx = table.partition_point(|&start| start <= off).saturating_sub(1);
    (line_idx + 1, off - table[line_idx] + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_line_table() {
        let src = b"abc\ndef\nghi";
        let table = build_line_table(src);
        assert_eq!(table, vec![0, 4, 8]);

        assert_eq!(line_col_from_table(&table, ByteOffset(0)), (1, 1));
        assert_eq!(line_col_from_table(&table, ByteOffset(2)), (1, 3));
        assert_eq!(line_col_from_table(&table, ByteOffset(4)), (2, 1));
        assert_eq!(line_col_from_table(&table, ByteOffset(8)), (3, 1));
        assert_eq!(line_col_from_table(&table, ByteOffset(10)), (3, 3));
    }

    #[test]
    fn synthetic_offset() {
        let table = build_line_table(b"hello");
        assert_eq!(line_col_from_table(&table, ByteOffset::SYNTHETIC), (0, 0));
    }

    #[test]
    fn empty_table() {
        assert_eq!(line_col_from_table(&[], ByteOffset(0)), (0, 0));
    }
}

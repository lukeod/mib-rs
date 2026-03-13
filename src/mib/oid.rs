use smallvec::SmallVec;
use std::fmt;
use std::str::FromStr;

/// An SNMP Object Identifier (OID), stored as a sequence of `u32` arcs.
///
/// Uses `SmallVec` for inline storage of OIDs with up to 16 arcs, which
/// covers most real-world OIDs without heap allocation.
///
/// Derefs to `[u32]`, so standard slice methods (`len`, `is_empty`,
/// `starts_with`, indexing) work directly.
///
/// # Parsing
///
/// ```
/// use mib_rs::mib::Oid;
///
/// let oid: Oid = "1.3.6.1.2.1".parse().unwrap();
/// assert_eq!(oid.len(), 6);
/// assert_eq!(oid[0], 1);
///
/// // Leading dot is accepted
/// let oid2: Oid = ".1.3.6.1.2.1".parse().unwrap();
/// assert_eq!(oid, oid2);
/// ```
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(SmallVec<[u32; 16]>);

impl Oid {
    /// Returns the last arc, if any.
    #[must_use]
    pub fn last_arc(&self) -> Option<u32> {
        self.0.last().copied()
    }

    /// Returns the parent OID (all arcs except the last).
    #[must_use]
    pub fn parent(&self) -> Option<Oid> {
        if self.0.len() <= 1 {
            return None;
        }
        Some(Oid(SmallVec::from_slice(&self.0[..self.0.len() - 1])))
    }

    /// Returns a child OID with the given arc appended.
    #[must_use]
    pub fn child(&self, arc: u32) -> Oid {
        let mut arcs = self.0.clone();
        arcs.push(arc);
        Oid(arcs)
    }
}

impl std::ops::Deref for Oid {
    type Target = [u32];

    fn deref(&self) -> &[u32] {
        &self.0
    }
}

impl AsRef<[u32]> for Oid {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl From<&[u32]> for Oid {
    fn from(arcs: &[u32]) -> Self {
        Oid(SmallVec::from_slice(arcs))
    }
}

impl From<Vec<u32>> for Oid {
    fn from(arcs: Vec<u32>) -> Self {
        Oid(SmallVec::from_vec(arcs))
    }
}

/// Parses dotted-decimal notation, with or without a leading dot.
///
/// Accepts `"1.3.6.1"` and `".1.3.6.1"`.
impl FromStr for Oid {
    type Err = ParseOidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix('.').unwrap_or(s);
        if s.is_empty() {
            return Err(ParseOidError::Empty);
        }
        let mut arcs = SmallVec::new();
        for part in s.split('.') {
            if part.is_empty() {
                return Err(ParseOidError::Empty);
            }
            let arc: u32 = part
                .parse()
                .map_err(|_| ParseOidError::InvalidArc(part.to_string()))?;
            arcs.push(arc);
        }
        Ok(Oid(arcs))
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self)
    }
}

/// Error parsing an OID string.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseOidError {
    /// The input string was empty or contained only a dot.
    #[error("empty OID")]
    Empty,
    /// An arc component could not be parsed as a u32.
    #[error("invalid arc: {0}")]
    InvalidArc(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(&*oid, &[1, 3, 6, 1]);
        assert_eq!(oid.to_string(), "1.3.6.1");
    }

    #[test]
    fn parse_leading_dot() {
        let oid: Oid = ".1.3.6.1".parse().unwrap();
        assert_eq!(&*oid, &[1, 3, 6, 1]);
    }

    #[test]
    fn parse_empty() {
        assert!("".parse::<Oid>().is_err());
    }

    #[test]
    fn parse_invalid() {
        assert!("1.3.abc".parse::<Oid>().is_err());
    }

    #[test]
    fn from_slice() {
        let oid = Oid::from([1u32, 3, 6, 1].as_slice());
        assert_eq!(&*oid, &[1, 3, 6, 1]);
    }

    #[test]
    fn from_vec() {
        let oid = Oid::from(vec![1u32, 3, 6, 1]);
        assert_eq!(&*oid, &[1, 3, 6, 1]);
    }

    #[test]
    fn default_is_empty() {
        let oid = Oid::default();
        assert!(oid.is_empty());
        assert_eq!(oid.len(), 0);
    }

    #[test]
    fn deref_gives_slice_methods() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(oid.len(), 4);
        assert!(!oid.is_empty());
        assert_eq!(oid.iter().sum::<u32>(), 11);
        assert_eq!(oid[2], 6);
    }

    #[test]
    fn as_ref_works() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let slice: &[u32] = oid.as_ref();
        assert_eq!(slice, &[1, 3, 6, 1]);
    }

    #[test]
    fn parent_child() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let parent = oid.parent().unwrap();
        assert_eq!(parent.to_string(), "1.3.6");

        let child = parent.child(1);
        assert_eq!(child, oid);
    }

    #[test]
    fn prefix() {
        let oid: Oid = "1.3.6.1.2.1".parse().unwrap();
        let prefix: Oid = "1.3.6.1".parse().unwrap();
        assert!(oid.starts_with(&prefix));
        assert!(!prefix.starts_with(&oid));
    }

    #[test]
    fn ordering() {
        let a: Oid = "1.3.6.1".parse().unwrap();
        let b: Oid = "1.3.6.2".parse().unwrap();
        let c: Oid = "1.3.6.1.1".parse().unwrap();
        assert!(a < b);
        assert!(a < c);
    }

    #[test]
    fn last_arc() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(oid.last_arc(), Some(1));
        assert_eq!(Oid::default().last_arc(), None);
    }

    #[test]
    fn single_arc_parent() {
        let oid: Oid = "1".parse().unwrap();
        assert!(oid.parent().is_none());
    }

    #[test]
    fn has_prefix() {
        let oid: Oid = "1.3.6.1.2.1".parse().unwrap();
        let prefix: Oid = "1.3.6.1".parse().unwrap();
        let other: Oid = "1.3.5".parse().unwrap();

        assert!(oid.starts_with(&prefix));
        assert!(oid.starts_with(&oid)); // self is a prefix of self
        assert!(!prefix.starts_with(&oid)); // shorter is not prefixed by longer
        assert!(!oid.starts_with(&other));
        assert!(oid.starts_with(&Oid::default())); // empty prefix matches all
    }
}

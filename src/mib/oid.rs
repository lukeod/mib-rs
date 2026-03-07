use smallvec::SmallVec;
use std::fmt;

/// An SNMP OID (Object Identifier), stored as a sequence of arc values.
/// Uses SmallVec for inline storage of OIDs with up to 16 arcs (covers most real OIDs).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(SmallVec<[u32; 16]>);

impl Oid {
    /// Create an empty OID.
    pub fn empty() -> Self {
        Oid(SmallVec::new())
    }

    /// Create an OID from a slice of arc values.
    pub fn from_arcs(arcs: &[u32]) -> Self {
        Oid(SmallVec::from_slice(arcs))
    }

    /// Parse an OID from dotted notation (e.g., "1.3.6.1.2.1").
    /// Leading dot is accepted and stripped.
    pub fn parse(s: &str) -> Result<Self, ParseOidError> {
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

    /// Returns the arcs as a slice.
    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    /// Returns the number of arcs.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the OID has no arcs.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the last arc, if any.
    pub fn last_arc(&self) -> Option<u32> {
        self.0.last().copied()
    }

    /// Returns the parent OID (all arcs except the last).
    pub fn parent(&self) -> Option<Oid> {
        if self.0.len() <= 1 {
            return None;
        }
        Some(Oid(SmallVec::from_slice(&self.0[..self.0.len() - 1])))
    }

    /// Returns a child OID with the given arc appended.
    pub fn child(&self, arc: u32) -> Oid {
        let mut arcs = self.0.clone();
        arcs.push(arc);
        Oid(arcs)
    }

    /// Returns true if this OID starts with the given prefix.
    pub fn has_prefix(&self, prefix: &Oid) -> bool {
        self.0.len() >= prefix.0.len() && self.0[..prefix.0.len()] == prefix.0[..]
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
    #[error("empty OID")]
    Empty,
    #[error("invalid arc: {0}")]
    InvalidArc(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let oid = Oid::parse("1.3.6.1").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1]);
        assert_eq!(oid.to_string(), "1.3.6.1");
    }

    #[test]
    fn parse_leading_dot() {
        let oid = Oid::parse(".1.3.6.1").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1]);
    }

    #[test]
    fn parse_empty() {
        assert!(Oid::parse("").is_err());
    }

    #[test]
    fn parse_invalid() {
        assert!(Oid::parse("1.3.abc").is_err());
    }

    #[test]
    fn parent_child() {
        let oid = Oid::parse("1.3.6.1").unwrap();
        let parent = oid.parent().unwrap();
        assert_eq!(parent.to_string(), "1.3.6");

        let child = parent.child(1);
        assert_eq!(child, oid);
    }

    #[test]
    fn prefix() {
        let oid = Oid::parse("1.3.6.1.2.1").unwrap();
        let prefix = Oid::parse("1.3.6.1").unwrap();
        assert!(oid.has_prefix(&prefix));
        assert!(!prefix.has_prefix(&oid));
    }

    #[test]
    fn ordering() {
        let a = Oid::parse("1.3.6.1").unwrap();
        let b = Oid::parse("1.3.6.2").unwrap();
        let c = Oid::parse("1.3.6.1.1").unwrap();
        assert!(a < b);
        assert!(a < c);
    }

    #[test]
    fn last_arc() {
        let oid = Oid::parse("1.3.6.1").unwrap();
        assert_eq!(oid.last_arc(), Some(1));
        assert_eq!(Oid::empty().last_arc(), None);
    }

    #[test]
    fn single_arc_parent() {
        let oid = Oid::parse("1").unwrap();
        assert!(oid.parent().is_none());
    }
}

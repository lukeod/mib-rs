//! Owned normalized constraint sets used by index schemas.

/// An inclusive, concrete interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusiveRange<T> {
    start: T,
    end: T,
}

impl<T> InclusiveRange<T> {
    /// Construct an inclusive interval.
    #[must_use]
    pub const fn new(start: T, end: T) -> Self {
        Self { start, end }
    }

    /// Inclusive lower endpoint.
    #[must_use]
    pub const fn start(&self) -> &T {
        &self.start
    }

    /// Inclusive upper endpoint.
    #[must_use]
    pub const fn end(&self) -> &T {
        &self.end
    }
}

impl<T: Ord> InclusiveRange<T> {
    pub(crate) fn contains(&self, value: &T) -> bool {
        self.start <= *value && *value <= self.end
    }
}

/// An interval with one or more unresolved endpoints.
///
/// A missing endpoint is unknown, rather than unbounded. This permits the
/// codec to distinguish a proven violation from an indeterminate value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialRange<T> {
    minimum: Option<T>,
    maximum: Option<T>,
}

impl<T> PartialRange<T> {
    /// Construct an interval with optional proven endpoints.
    #[must_use]
    pub const fn new(minimum: Option<T>, maximum: Option<T>) -> Self {
        Self { minimum, maximum }
    }

    /// Proven inclusive lower endpoint, when available.
    #[must_use]
    pub const fn minimum(&self) -> Option<&T> {
        self.minimum.as_ref()
    }

    /// Proven inclusive upper endpoint, when available.
    #[must_use]
    pub const fn maximum(&self) -> Option<&T> {
        self.maximum.as_ref()
    }
}

impl<T: Ord> PartialRange<T> {
    fn could_contain(&self, value: &T) -> bool {
        self.minimum.as_ref().is_none_or(|minimum| minimum <= value)
            && self.maximum.as_ref().is_none_or(|maximum| value <= maximum)
    }
}

/// Result of checking a value against owned constraint metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstraintCheck {
    /// The value is accepted by a concrete alternative or no constraint exists.
    Allowed,
    /// The value is rejected by every effective alternative.
    Violation,
    /// Unresolved metadata prevents either conclusion.
    Indeterminate,
}

/// A normalized union of inclusive ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizedConstraint<T> {
    /// No effective constraint was declared.
    Unspecified,
    /// All alternatives are concrete, sorted, and non-overlapping.
    Known(Box<[InclusiveRange<T>]>),
    /// Some alternatives have unresolved endpoints.
    Incomplete {
        /// Concrete alternatives known to admit values.
        known: Box<[InclusiveRange<T>]>,
        /// Alternatives retaining the endpoints that could be proven.
        partial: Box<[PartialRange<T>]>,
    },
    /// A constraint was declared but its effective intersection is empty.
    Empty,
}

impl<T: Ord> NormalizedConstraint<T> {
    /// Check a value without treating unresolved metadata as either acceptance
    /// or rejection.
    #[must_use]
    pub fn check(&self, value: &T) -> ConstraintCheck {
        match self {
            Self::Unspecified => ConstraintCheck::Allowed,
            Self::Empty => ConstraintCheck::Violation,
            Self::Known(ranges) => {
                if ranges.iter().any(|range| range.contains(value)) {
                    ConstraintCheck::Allowed
                } else {
                    ConstraintCheck::Violation
                }
            }
            Self::Incomplete { known, partial } => {
                if known.iter().any(|range| range.contains(value)) {
                    ConstraintCheck::Allowed
                } else if partial.iter().any(|range| range.could_contain(value)) {
                    ConstraintCheck::Indeterminate
                } else {
                    ConstraintCheck::Violation
                }
            }
        }
    }

    /// Return the sole accepted value when the constraint is completely known
    /// and contains exactly one singleton interval.
    #[must_use]
    pub fn exact_value(&self) -> Option<&T> {
        match self {
            Self::Known(ranges) if ranges.len() == 1 && ranges[0].start() == ranges[0].end() => {
                Some(ranges[0].start())
            }
            _ => None,
        }
    }

    /// Largest concrete upper endpoint when the complete set is known.
    #[must_use]
    pub fn known_maximum(&self) -> Option<&T> {
        match self {
            Self::Known(ranges) => ranges.last().map(InclusiveRange::end),
            _ => None,
        }
    }

    /// Smallest proven lower bound across every effective alternative.
    ///
    /// Returns `None` when any alternative has an unresolved lower endpoint.
    #[must_use]
    pub fn proven_minimum(&self) -> Option<&T> {
        match self {
            Self::Known(ranges) => ranges.first().map(InclusiveRange::start),
            Self::Incomplete { known, partial } => {
                if partial.iter().any(|range| range.minimum().is_none()) {
                    return None;
                }
                known
                    .iter()
                    .map(InclusiveRange::start)
                    .chain(partial.iter().filter_map(PartialRange::minimum))
                    .min()
            }
            Self::Unspecified | Self::Empty => None,
        }
    }

    /// Largest proven finite upper bound across every effective alternative.
    ///
    /// Returns `None` when any alternative has an unresolved upper endpoint.
    #[must_use]
    pub fn proven_maximum(&self) -> Option<&T> {
        match self {
            Self::Known(ranges) => ranges.last().map(InclusiveRange::end),
            Self::Incomplete { known, partial } => {
                if partial.iter().any(|range| range.maximum().is_none()) {
                    return None;
                }
                known
                    .iter()
                    .map(InclusiveRange::end)
                    .chain(partial.iter().filter_map(PartialRange::maximum))
                    .max()
            }
            Self::Unspecified | Self::Empty => None,
        }
    }

    /// Whether any endpoint could not be resolved.
    #[must_use]
    pub const fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

pub(crate) fn normalize_i64(
    ranges: &[crate::mib::types::Range],
    constrained: bool,
    primitive_minimum: i64,
    primitive_maximum: i64,
) -> NormalizedConstraint<i64> {
    if !constrained {
        return NormalizedConstraint::Unspecified;
    }
    normalize(
        ranges,
        |bound| match bound {
            crate::mib::types::RangeBound::Signed(value) => Some(*value),
            crate::mib::types::RangeBound::Unsigned(value) => {
                Some(i64::try_from(*value).unwrap_or(i64::MAX))
            }
            crate::mib::types::RangeBound::Min
            | crate::mib::types::RangeBound::Max
            | crate::mib::types::RangeBound::Raw(_) => None,
        },
        primitive_minimum,
        primitive_maximum,
    )
}

pub(crate) fn normalize_usize(
    ranges: &[crate::mib::types::Range],
    constrained: bool,
) -> NormalizedConstraint<usize> {
    if !constrained {
        return NormalizedConstraint::Unspecified;
    }
    normalize(
        ranges,
        |bound| bound.as_u64().and_then(|value| usize::try_from(value).ok()),
        0,
        usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    )
}

fn normalize<T, F>(
    ranges: &[crate::mib::types::Range],
    convert: F,
    primitive_minimum: T,
    primitive_maximum: T,
) -> NormalizedConstraint<T>
where
    T: ConstraintNumber,
    F: Fn(&crate::mib::types::RangeBound) -> Option<T>,
{
    if ranges.is_empty() {
        return NormalizedConstraint::Empty;
    }

    let mut known = Vec::new();
    let mut partial = Vec::new();
    for range in ranges {
        let minimum = convert(&range.min);
        let maximum = convert(&range.max);

        if minimum.is_some_and(|value| value > primitive_maximum)
            || maximum.is_some_and(|value| value < primitive_minimum)
        {
            continue;
        }

        match (minimum, maximum) {
            (Some(minimum), Some(maximum)) => {
                let minimum = minimum.max(primitive_minimum);
                let maximum = maximum.min(primitive_maximum);
                if minimum <= maximum {
                    known.push(InclusiveRange::new(minimum, maximum));
                }
            }
            (minimum, maximum) => partial.push(PartialRange::new(
                minimum.map(|value| value.max(primitive_minimum)),
                maximum.map(|value| value.min(primitive_maximum)),
            )),
        }
    }

    merge_ranges(&mut known);
    if partial.is_empty() {
        if known.is_empty() {
            NormalizedConstraint::Empty
        } else {
            NormalizedConstraint::Known(known.into_boxed_slice())
        }
    } else {
        NormalizedConstraint::Incomplete {
            known: known.into_boxed_slice(),
            partial: partial.into_boxed_slice(),
        }
    }
}

fn merge_ranges<T: ConstraintNumber>(ranges: &mut Vec<InclusiveRange<T>>) {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<InclusiveRange<T>> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(previous) = merged.last_mut()
            && T::overlaps_or_adjacent(range.start, previous.end)
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    *ranges = merged;
}

trait ConstraintNumber: Copy + Ord {
    fn overlaps_or_adjacent(start: Self, previous_end: Self) -> bool;
}

impl ConstraintNumber for i64 {
    fn overlaps_or_adjacent(start: Self, previous_end: Self) -> bool {
        start <= previous_end
            || previous_end
                .checked_add(1)
                .is_some_and(|adjacent| start <= adjacent)
    }
}

impl ConstraintNumber for usize {
    fn overlaps_or_adjacent(start: Self, previous_end: Self) -> bool {
        start <= previous_end
            || previous_end
                .checked_add(1)
                .is_some_and(|adjacent| start <= adjacent)
    }
}

#[cfg(test)]
mod tests {
    use crate::mib::types::{Range, RangeBound};
    use crate::types::Span;

    use super::{InclusiveRange, NormalizedConstraint, normalize_usize};

    fn range(minimum: u64, maximum: u64) -> Range {
        Range {
            min: RangeBound::Unsigned(minimum),
            max: RangeBound::Unsigned(maximum),
            span: Span::SYNTHETIC,
        }
    }

    #[test]
    fn normalization_merges_overlapping_and_adjacent_alternatives() {
        let normalized =
            normalize_usize(&[range(8, 11), range(1, 1), range(3, 8), range(2, 2)], true);
        assert_eq!(
            normalized,
            NormalizedConstraint::Known(vec![InclusiveRange::new(1, 11)].into_boxed_slice())
        );
    }
}

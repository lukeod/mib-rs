# Embedded foundation modules

These RFC-derived module sources are compiled into `mib-rs` as lowest-priority
fallbacks. The module files are maintained byte-for-byte in sync with gomib.
They contain the ASN.1/SMI definitions only: surrounding RFC prose, page
headers, footers, and pagination are omitted, and layout may be normalized.

- `RFC1065-SMI`: RFC 1065
- `RFC1155-SMI`: RFC 1155
- `RFC-1212`: RFC 1212
- `RFC-1215`: RFC 1215
- `SNMPv2-SMI`: RFC 2578
- `SNMPv2-TC`: RFC 2579
- `SNMPv2-CONF`: RFC 2580

Configured MIB sources take precedence on a per-module basis. Complete
embedded modules therefore preserve the RFC definitions so choosing the
fallback does not change definition kinds or metadata. In particular,
`SNMPv2-SMI` does not add explicit definitions for the intrinsic ASN.1 root
arcs or convert its administrative `OBJECT IDENTIFIER` assignments into
`OBJECT-IDENTITY` definitions. Well-known root handling belongs to the
resolver and applies equally to configured and embedded sources.

The only deliberate source changes are those needed to make incomplete RFC
excerpts usable as self-contained foundation modules, plus explanatory
comments:

- `RFC-1212` and `RFC-1215` add module headers and closing `END` statements.
  The RFCs present these macro definitions as excerpts rather than complete
  named modules, while real MIBs conventionally import `OBJECT-TYPE` from
  `RFC-1212` and `TRAP-TYPE` from `RFC-1215`.
- `RFC-1212` terminates the `RFC1155-SMI` import separately and comments out
  the RFC's `DisplayString FROM RFC1158-MIB` import. This avoids making the
  foundation fallback depend on the non-embedded `RFC1158-MIB`; the remaining
  `DisplayString` references occur only inside the macro notation.
- `RFC1065-SMI` adds a comment explaining that its unconstrained `TimeTicks`
  definition is intentional. RFC 1155 added the `(0..4294967295)` constraint,
  but that later constraint must not be applied to a type imported from
  `RFC1065-SMI`.

`RFC1155-SMI`, `SNMPv2-SMI`, `SNMPv2-TC`, and `SNMPv2-CONF` have no substantive
changes to their RFC definitions beyond extraction and layout cleanup.

# Embedded foundation modules

These RFC-derived module sources are compiled into `mib-rs` as lowest-priority
fallbacks. They are maintained byte-for-byte in sync with gomib and include
deliberate adaptations rather than literal reproductions of the RFC text:

- `RFC1065-SMI`: RFC 1065
- `RFC1155-SMI`: RFC 1155
- `RFC-1212`: RFC 1212
- `RFC-1215`: RFC 1215
- `SNMPv2-SMI`: RFC 2578
- `SNMPv2-TC`: RFC 2579
- `SNMPv2-CONF`: RFC 2580

Configured MIB sources take precedence over these files.

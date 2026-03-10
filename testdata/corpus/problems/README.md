## PROBLEM Corpus Enterprise Allocations

The synthetic `PROBLEM-*` corpus intentionally reserves a small set of test-only
enterprise subtrees so fixtures do not accidentally collide with each other.

- `enterprises.99990`: `PROBLEM-MULTIMOD-BASE-MIB`
- `enterprises.99997`: `PROBLEM-P3-IMPORTS-MIB`
- `enterprises.99998.1`: `PROBLEM-SMIv1v2-MIX-MIB`
- `enterprises.99998.2`: `PROBLEM-IMPORTS-MIB`
- `enterprises.99998.3`: `PROBLEM-IMPORTS-ALIAS-MIB`
- `enterprises.99998.4`: `PROBLEM-KEYWORDS-MIB`
- `enterprises.99998.5`: `PROBLEM-INDEX-MIB`
- `enterprises.99998.6`: `PROBLEM-DEFVAL-MIB`
- `enterprises.99998.7`: `PROBLEM-NAMING-MIB`
- `enterprises.99998.8`: `PROBLEM-NOTIFICATIONS-MIB`
- `enterprises.99998.9`: `PROBLEM-ACCESS-MIB`
- `enterprises.99998.10`: `PROBLEM-HEXSTRINGS-MIB`
- `enterprises.99998.11`: `PROBLEM-REVISIONS-MIB`
- `enterprises.99998.20`: `PROBLEM-FORWARDING-SOURCE-MIB`
- `enterprises.99998.21`: `PROBLEM-FORWARDING-RELAY-MIB`
- `enterprises.99998.22`: `PROBLEM-FORWARDING-MIB`
- `enterprises.99998.23`: `PROBLEM-TYPECHAINS-MIB`
- `enterprises.99998.24`: `PROBLEM-SEMANTICS-MIB`
- `enterprises.99998.25`: `PROBLEM-DIAGNOSTICS-MIB`
- `enterprises.99998.26`: `PROBLEM-SHADOWING-MIB`
- `enterprises.99998.30`: `PROBLEM-SHARED-OIDS-BASE-MIB`
- `enterprises.99998.31`: `PROBLEM-SHARED-OIDS-MIB`
- `enterprises.99998.32`: `PROBLEM-CASEFOLDING-MIB`
- `enterprises.99998.33`: `PROBLEM-ENUM-SUBTYPE-MIB`
- `enterprises.99998.34`: `PROBLEM-RANGES-MIB`
- `enterprises.99998.35`: `PROBLEM-ENUM-BITS-DUPES-MIB`
- `enterprises.99998.36`: `PROBLEM-SHADOWING-BASE-MIB`
- `enterprises.99998.37`: `PROBLEM-GROUP-MEMBERSHIP-MIB`
- `enterprises.99998.38`: `PROBLEM-PARTIAL-IMPORTS-MIB`
- `enterprises.99998.39`: `PROBLEM-STRICT-METADATA-MIB`
- `enterprises.99998.40`: `PROBLEM-SEMANTIC-GLOBAL-SOURCE-MIB`
- `enterprises.99998.41`: `PROBLEM-SEMANTIC-GLOBAL-MIB`
- `enterprises.99999`: `PROBLEM-DUPLICATE-IMPORT-MIB`

Notes:

- `PROBLEM-MULTIMOD.mib` contains two modules. Only the base module claims a
  direct `enterprises.*` root; the leaf module is rooted under that base.
- The forwarding fixtures intentionally reserve a contiguous block
  `99998.20`-`99998.22`.
- The shared OID fixtures intentionally reserve `99998.30` and `99998.31`.
- The semantic global fixtures intentionally reserve `99998.40` and `99998.41`.

Update this file and `TestProblemCorpusEnterpriseAllocations` together when a
new synthetic fixture needs a direct `enterprises.*` root.

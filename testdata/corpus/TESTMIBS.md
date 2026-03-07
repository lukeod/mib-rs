# Test MIB Corpus

A curated collection of 196 real-world MIBs for integration testing.

## Structure

```
corpus/
├── primary/           # Main corpus - self-contained, all deps included
│   ├── ietf/          # IETF/RFC standards (64)
│   ├── iana/          # IANA registries (5)
│   ├── ieee/          # IEEE standards (8)
│   ├── cisco/         # Cisco/Linksys (10)
│   ├── juniper/       # Juniper (16)
│   ├── alcatel/       # Alcatel/Nokia/Timetra (34)
│   ├── huawei/        # Huawei (8)
│   ├── adva/          # ADVA/FSP/Tropic (17)
│   ├── net-snmp/      # Net-SNMP/UCD (3)
│   ├── misc/          # Other vendors (29)
│   └── synthetic/     # Purpose-built test MIBs (2)
└── <future>/          # Edge-case corpora as needed
```

## Usage

```go
// Load with recursive directory traversal
src, _ := loader.Dir("testdata/corpus/primary")
l := loader.New(src)
l.Load("IF-MIB")  // finds ietf/IF-MIB.mib
```

```bash
# CLI
gomib load -p ./testdata/corpus/primary IF-MIB IP-MIB
```

## Selection Criteria

MIBs were selected for maximum diversity:
- SMIv1 and SMIv2 coverage
- TRAP-TYPE (SMIv1) and NOTIFICATION-TYPE (SMIv2)
- AUGMENTS, IMPLIED INDEX, deep compound indices
- TEXTUAL-CONVENTION, BITS, enumerated INTEGER
- MODULE-COMPLIANCE, AGENT-CAPABILITIES
- Range from minimal to very large MIBs (10k+ objects)

## File Naming

All files use `.mib` extension for consistency.

## Known Issues

These MIBs have intentional defects and are included as test targets for error handling:

### PRVT-SERV-MIB.mib (misc/)

**Issue:** Imports `serviceAccessSwitch` from wrong module.

The MIB imports `serviceAccessSwitch FROM PRVT-QOS-MIB` but that identifier is
actually defined in PRVT-SWITCH-MIB. PRVT-QOS-MIB only imports it for its own
use and does not re-export it.

**Expected behavior:** Parsers should report an unresolved import. The module
will partially resolve but `prvtServicesMIB` and its children will have
unlinked OIDs.

**Test value:** Exercises import resolution error handling and graceful
degradation when dependencies are incorrectly specified.

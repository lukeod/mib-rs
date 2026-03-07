# Strictness Test Corpus

Mini MIB corpus for testing gomib strictness levels against libsmi (smilint) and net-snmp.

## Directory Structure

```
strictness/
  strict/      RFC-compliant MIBs (pass smilint -l 1)
  relaxed/     MIBs with minor issues (warnings only)
  violations/  MIBs with specific violations for testing diagnostics
  invalid/     MIBs that should fail at all levels
```

## Test MIBs

### strict/

RFC-compliant SMIv2 MIBs that pass smilint at level 1 (severe errors only).

- **STRICT-TEST-MIB.mib** - Minimal compliant MIB with scalars
- **STRICT-TABLE-MIB.mib** - Compliant MIB with a table

```bash
# Validation
smilint -l 1 strict/STRICT-TEST-MIB.mib   # No output (passes)
snmptranslate -M strict -m STRICT-TEST-MIB -IR strictTestString   # Works
```

### violations/

MIBs with specific RFC violations for testing diagnostic emission.

- **UNDERSCORE-TEST-MIB.mib** - Underscores in identifiers (RFC 2578 Section 3.1)
  - Diagnostic: `identifier-underscore` (Style level in gomib, Error level 2 in smilint)
  - smilint: `[2] identifier 'test_object' must not contain an underscore`
  - net-snmp: Fails by default, works with `-Pu` flag

- **HYPHEN-END-TEST-MIB.mib** - Identifier ending with hyphen (RFC 2578 Section 3.1)
  - Diagnostic: `identifier-hyphen-end` (Error level)
  - smilint: `[2] identifier 'testObject-' illegally ends in a hyphen`
  - net-snmp: Loads (more permissive)

- **LONG-IDENT-TEST-MIB.mib** - Identifier exceeding 64 characters (RFC 2578 Section 3.1)
  - Diagnostic: `identifier-length-64` (Error level)
  - smilint: `[2] object identifier name '...' must not be longer that 64 characters`
  - net-snmp: Loads (more permissive)

- **MISSING-IDENTITY-MIB.mib** - SMIv2 module without MODULE-IDENTITY (RFC 2578 Section 3)
  - Diagnostic: `missing-module-identity` (Warning level)
  - smilint: `[2] missing MODULE-IDENTITY clause in SMIv2 MIB`
  - net-snmp: Loads (more permissive)

### relaxed/

MIBs that pass at permissive level but have warnings at strict level.

- **LONG-NAME-WARN-MIB.mib** - Identifier exceeding 32 chars (RFC recommendation)
  - Diagnostic: `identifier-length-32` (Warning level)
  - smilint: No error (only warns above 64, not 32)
  - net-snmp: Loads

## smilint Severity Levels

| Level | Severity | Description |
|-------|----------|-------------|
| 0 | Fatal | Cannot continue (memory errors, loops) |
| 1 | Severe | Major errors (syntax, unknown keywords) |
| 2 | Error | Tolerated by some (underscore, hyphen-end, long names) |
| 3 | Minor | Likely tolerated (missing MODULE-IDENTITY position) |
| 4 | Style | Should change but not errors |
| 5 | Warning | Basically correct but might cause issues |
| 6 | Info | Auxiliary notices |

## gomib Strictness Mapping

| gomib --level | Internal | smilint Level | Use Case |
|---------------|----------|---------------|----------|
| 6 | Strict | 0-6 | RFC compliance validation |
| 3 | Normal | 0-3 | Default, balanced |
| 1 | Permissive | 0-5 | Legacy/vendor MIBs |
| 0 | Silent | - | Maximum compatibility |

## Usage

```bash
# Validate all strict MIBs pass
SMIPATH=../corpus/primary/ietf:../corpus/primary/iana:strict smilint -l 1 strict/*.mib

# Test gomib at different strictness levels
gomib load --strict -p . STRICT-TEST-MIB          # Should pass
gomib load --strict -p . UNDERSCORE-TEST-MIB      # Should emit identifier-underscore
gomib load --permissive -p . UNDERSCORE-TEST-MIB  # Should pass (suppressed)
```

## net-snmp Flags

| Flag | Description |
|------|-------------|
| -Pu | Allow underscores in MIB symbols |
| -Pc | Allow "--" terminated comments |
| -Pe | Disable errors on symbol conflicts |
| -Pw | Enable warnings on symbol conflicts |
| -PR | Replace symbols from latest module |

## Validation Commands

```bash
# Set SMIPATH to include standard MIBs
export CORPUS=/path/to/testdata/corpus/primary
export SMIPATH="$CORPUS/ietf:$CORPUS/iana"

# Test strict compliance
smilint -s -m -l 1 strict/STRICT-TEST-MIB.mib

# Test violation detection
smilint -s -m -l 6 violations/UNDERSCORE-TEST-MIB.mib

# Test with net-snmp
snmptranslate -M "$SMIPATH:strict" -m STRICT-TEST-MIB -IR strictTestString
snmptranslate -Pu -M "$SMIPATH:violations" -m UNDERSCORE-TEST-MIB -IR test_object
```

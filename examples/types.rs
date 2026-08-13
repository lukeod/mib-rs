//! Type chains, effective values, constraints, enums, display hints,
//! and classification predicates.

use mib_rs::{BaseType, Loader};

fn main() {
    let source = mib_rs::source::memory(
        "EXAMPLE-FULL-MIB",
        include_bytes!("../tests/data/example-full-mib.txt").as_slice(),
    );

    let mib = Loader::new()
        .source(source)
        .modules(["EXAMPLE-FULL-MIB"])
        .load()
        .expect("should load");

    // -- Textual convention with display hint --
    let ty = mib.r#type("ExPercentage").unwrap();
    println!("=== ExPercentage ===");
    println!("  Name:         {}", ty.name());
    println!("  Is TC:        {}", ty.is_textual_convention());
    println!("  Base:         {:?}", ty.base());
    println!("  Eff. base:    {:?}", ty.effective_base());
    println!("  Display hint: {:?}", ty.display_hint());
    println!("  Eff. hint:    {:?}", ty.effective_display_hint());
    println!("  Status:       {:?}", ty.status());
    println!("  Description:  {}", ty.description());
    assert_eq!(ty.effective_base(), BaseType::Integer32);
    assert_eq!(ty.effective_display_hint(), "d");

    // Range constraints
    let ranges = ty.effective_ranges();
    println!("  Ranges:");
    for r in ranges {
        println!("    {}..{}", r.min, r.max);
    }

    // -- Textual convention with size constraint --
    let ty = mib.r#type("ExName").unwrap();
    println!("\n=== ExName ===");
    println!("  Eff. base:    {:?}", ty.effective_base());
    println!("  Display hint: {:?}", ty.effective_display_hint());
    let sizes = ty.effective_sizes();
    println!("  Sizes:");
    for s in sizes {
        println!("    {}..{}", s.min, s.max);
    }
    assert!(ty.is_string());

    // -- Enumeration type --
    let ty = mib.r#type("ExDeviceStatus").unwrap();
    println!("\n=== ExDeviceStatus ===");
    println!("  Is TC:         {}", ty.is_textual_convention());
    println!("  Is enum:       {}", ty.is_enumeration());
    println!("  Eff. base:     {:?}", ty.effective_base());
    let enums = ty.effective_enums();
    println!("  Enum values:");
    for e in enums {
        println!("    {}({})", e.label, e.value);
    }

    // -- Type parent chain --
    // ExName -> DisplayString -> (base: OctetString)
    let ty = mib.r#type("ExName").unwrap();
    println!("\n=== Type chain: ExName ===");
    print_type_chain(&ty);

    // ExPercentage -> (base: Integer32)
    let ty = mib.r#type("ExPercentage").unwrap();
    println!("\n=== Type chain: ExPercentage ===");
    print_type_chain(&ty);

    // -- Type accessed through an object --
    let obj = mib.object("exIfSpeed").unwrap();
    let ty = obj.ty().unwrap();
    println!("\n=== exIfSpeed type ===");
    println!("  Type name:  {}", ty.name());
    println!("  Is gauge:   {}", ty.is_gauge());
    println!("  Eff. base:  {:?}", ty.effective_base());
    assert!(ty.is_gauge());

    // -- Counter type --
    let obj = mib.object("exUptime").unwrap();
    let ty = obj.ty().unwrap();
    println!("\n=== exUptime type ===");
    println!("  Type name:  {}", ty.name());
    println!("  Is counter: {}", ty.is_counter());
    assert!(ty.is_counter());

    // -- Effective accessors on Object (shortcut through type chain) --
    let obj = mib.object("exDeviceName").unwrap();
    println!("\n=== Object effective accessors ===");
    println!(
        "  exDeviceName.effective_display_hint: {:?}",
        obj.effective_display_hint()
    );
    println!(
        "  exDeviceName.effective_sizes:        {:?}",
        obj.effective_sizes()
    );

    let obj = mib.object("exDeviceStatus").unwrap();
    println!("  exDeviceStatus.effective_enums:");
    for e in obj.effective_enums() {
        println!("    {}({})", e.label, e.value);
    }

    // -- Display-hint formatting --
    //
    // Objects with a DISPLAY-HINT can format raw SNMP values directly.
    // Integer hints (d, d-N, x, o, b) format integer values.
    // Octet-string hints format byte slices.

    // ExHundredths has DISPLAY-HINT "d-2": 1234 -> "12.34"
    use mib_rs::mib::display_hint::{self, HexCase};
    let obj = mib.object("exTemperature").unwrap();
    println!("\n=== Display-hint formatting ===");
    println!("  hint:           {:?}", obj.effective_display_hint());
    println!(
        "  format(2345):   {:?}",
        obj.format_integer(2345, HexCase::Upper)
    );
    println!("  scale(2345):    {:?}", obj.scale_integer(2345));
    println!("  units:          {:?}", obj.units());
    assert_eq!(
        obj.format_integer(2345, HexCase::Upper),
        Some("23.45".into())
    );
    assert_eq!(obj.scale_integer(2345), Some(23.45));

    // ExMacAddress has DISPLAY-HINT "1x:": formats as colon-separated hex.
    let obj = mib.object("exDeviceMac").unwrap();
    let mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    println!(
        "  mac format:     {:?}",
        obj.format_octets(&mac, HexCase::Upper)
    );
    assert_eq!(
        obj.format_octets(&mac, HexCase::Upper),
        Some("00:1A:2B:3C:4D:5E".into())
    );

    // ExName has DISPLAY-HINT "255a": ASCII display.
    let obj = mib.object("exDeviceName").unwrap();
    println!(
        "  name format:    {:?}",
        obj.format_octets(b"switch-01", HexCase::Upper)
    );
    assert_eq!(
        obj.format_octets(b"switch-01", HexCase::Upper),
        Some("switch-01".into()),
    );

    // Objects without a display hint return None.
    let obj = mib.object("exUptime").unwrap();
    assert_eq!(obj.format_integer(12345, HexCase::Upper), None);

    // The display_hint module is also available for direct use without
    // an Object handle, e.g. when you have a hint string from elsewhere.
    assert_eq!(
        display_hint::format_integer("d-2", 1234, HexCase::Upper),
        Some("12.34".into())
    );
    assert_eq!(
        display_hint::format_octets("1d.1d.1d.1d", &[10, 0, 0, 1], HexCase::Upper),
        Some("10.0.0.1".into())
    );

    // -- Units clause --
    let obj = mib.object("exUptime").unwrap();
    println!("\n  exUptime.units: {:?}", obj.units());

    let obj = mib.object("exIfSpeed").unwrap();
    println!("  exIfSpeed.units: {:?}", obj.units());

    // -- DEFVAL --
    let obj = mib.object("exRebootEnabled").unwrap();
    if let Some(defval) = obj.default_value() {
        println!(
            "\n  exRebootEnabled.defval: {} (kind={:?})",
            defval,
            defval.kind()
        );
    }

    // -- Classification predicates --
    println!("\n=== Type classification ===");
    for name in ["ExName", "ExPercentage", "ExDeviceStatus"] {
        let ty = mib.r#type(name).unwrap();
        println!(
            "  {:<20} string={:<5} counter={:<5} gauge={:<5} enum={:<5} bits={:<5}",
            ty.name(),
            ty.is_string(),
            ty.is_counter(),
            ty.is_gauge(),
            ty.is_enumeration(),
            ty.is_bits(),
        );
    }

    // -- Iterate all types in the loaded MIB --
    println!("\n=== All user-defined types ===");
    let module = mib.module("EXAMPLE-FULL-MIB").unwrap();
    for ty in module.types() {
        let parent_name = ty
            .parent()
            .map(|p| p.name().to_string())
            .unwrap_or_default();
        println!(
            "  {:<20} base={:<16?} parent={:<20} tc={}",
            ty.name(),
            ty.effective_base(),
            parent_name,
            ty.is_textual_convention(),
        );
    }
}

fn print_type_chain(ty: &mib_rs::Type<'_>) {
    let mut current = Some(*ty);
    let mut depth = 0;
    while let Some(t) = current {
        let indent = "  ".repeat(depth + 1);
        let hint = t.display_hint();
        let hint_str = if hint.is_empty() {
            String::new()
        } else {
            format!("  hint={hint:?}")
        };
        println!(
            "{}{} (base={:?}, tc={}{})",
            indent,
            t.name(),
            t.base(),
            t.is_textual_convention(),
            hint_str,
        );
        current = t.parent();
        depth += 1;
    }
}

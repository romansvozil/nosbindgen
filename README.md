# nosbindgen
Simple utility for generating Rust bindings for Nostale. Is it useful? Maybe


### Example config.yaml:
```yaml
- name: StrFromLStr
  pattern: '31 c9 85 d2 74 ? 8b 4a ? e9'
  arguments:
      - name: 'destination'
        type: '*mut c_void'
      - name: lstr
        type: '*const c_void'
```

```shell script
python bindgen.py --exe NostaleClientX.exe --conf config.yaml --out bindings.rs
```

## Result bindings.rs:
```rust
pub fn walk(unknown2: u32, unknown1: u32, position: u32, pmanager: *mut c_void) -> u32 { 
    let mut eax = pmanager as u32;
    unsafe { asm! { "push {unknown2}",
        "call {fn}",
        fn = in(reg) 0x53d868, unknown2 = in(reg) unknown2, in("ecx") unknown1, in("edx") position, inout("eax") eax
    } };
    eax
}
```
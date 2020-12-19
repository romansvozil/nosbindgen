# nosbindgen
Simple utility for generating Rust bindings for Nostale. Is it useful? Maybe


### Example config.yaml:
```yaml
imports:
  - 'winapi::ctypes::c_void'
functions:
  - name: 'walk'
    pattern: '55 8B EC 0x83 C4 EC 53 56 57 66 89 4D FA'
    arguments:
      - name: pmanager
        type: '*mut c_void'
      - name: position
        type: 'u32'
      - name: unknown1
        type: u32
      - name: unknown2
        type: u32
```

```shell script
python bindgen.py --exe NostaleClientX.exe --conf config.yaml --out bindings.rs
```

## Result bindings.rs:
```rust
use winapi::ctypes::c_void;

pub fn walk(pmanager: *mut c_void, position: u32, unknown1: u32, unknown2: u32) -> u32 { 
    let mut eax = pmanager as u32;
    unsafe { asm! { "push {unknown2}",
        "call {fn}",
        fn = in(reg) 0x53d868, unknown2 = in(reg) unknown2, inout("eax") eax, in("edx") position, in("ecx") unknown1
    } };
    eax
}
```
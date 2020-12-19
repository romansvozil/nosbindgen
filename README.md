# nosbindgen
Automaticaly creates Rust bindings from patterns for Nostale.


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
```rs
- name: StrFromLStr
  pattern: '31 c9 85 d2 74 ? 8b 4a ? e9'
  arguments:
      - name: 'destination'
        type: '*mut c_void'
      - name: lstr
        type: '*const c_void'
```
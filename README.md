# super_license

## design
license schema:
- magic: "super_license"
- version(uint32): 1
- raw_len(uint64): 0, no raw data; > 0, include raw data
- [raw_data]: base on raw_len
- data_len(uint64)

    - key_len(uint16)
    - key_data: base on key_len
    - ciphertext_len(uint64)
    - ciphertext: base on ciphertext_len

> version and xxx_len use bigendian

demo license schema:
- ID
- AuthList([]Auth)

    Auth:
    - Code
    - Name
    - Content
    - ExpiredAt

- CreatedAt

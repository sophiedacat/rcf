# rcf
### your code cant change if you dont let it

# ok hows it work?
it works by hashing every executable non writable page of your module at startup then rehashing on demand and comparing if the bytes magically changed

# important notes:
- no crt
- x64 only (if you're still deving x86 why..)
- does not catch hardware breakpoints (durh)
- does not catch iat hooks
- catches software breakpoints inline hooks and patches to text
- `attest_verify` self hashes the hashing routine with a different seed call it from another thread so a single hook cant cover both

# usage
all example usage inside example.cxx

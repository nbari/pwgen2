[![Test & Build](https://github.com/nbari/pwgen2/actions/workflows/build.yml/badge.svg)](https://github.com/nbari/pwgen2/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/nbari/pwgen2/graph/badge.svg?token=IUHSFDK6XD)](https://codecov.io/gh/nbari/pwgen2)

# pwgen2


password generator

Default length is 18 characters, but can be changed with the first argument.

```bash
pwgen2 24
```

Password is generated using the following characters:

```
lowercase: "abcdefghijklmnopqrstuvwxyz",
uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
digits: "0123456789",
symbols: "!@#$%&.-_*",
```

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

Generated passwords keep symbols sparse and never start with a symbol.

## Installation

```bash
cargo install pwgen2
```

## Usage

```text
Usage: pwgen2 [OPTIONS] [length] [number]

Arguments:
  [length]
          password length
          
          [default: 18]

  [number]
          Number of passwords to generate
          
          [default: 1]

Options:
  -p, --pin
          Generate a pin

  -a, --alphanumeric
          Generate an alphanumeric password

  -m, --mnemonic [<words>]
          Generate a standard English BIP-39 mnemonic phrase. Omitting the count defaults to 12 words.

  -b, --bcrypt
          Hash the generated password using Bcrypt

  -k, --pbkdf2
          Hash the generated password using PBKDF2

  -s, --sha512
          Hash the generated password using SHA512

  -c, --charset <symbols>
          Symbols to use for password generation. Passwords keep symbols sparse and never start with a symbol.

  -j, --json
          Output as JSON

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Notes:
  Generated passwords keep symbols sparse and never start with a symbol.
  --mnemonic generates a standard English BIP-39 recovery phrase.
```

## Examples

Create a password with 24 characters:

```bash
pwgen2 24
```

Create a pin:

```bash
pwgen2 -p
```

Create an alphanumeric password:

```bash
pwgen2 -a
```

Create 5 passwords with 24 characters:

```bash
pwgen2 24 5
```

Create a password and hash it using Bcrypt:

```bash
pwgen2 -b
```
> useful for generating passwords for htpasswd

Create passwords as JSON:

```bash
pwgen2 -j 18 3
```

Create passwords with a custom symbol set:

```bash
pwgen2 -c '~€' 20 3
```

Create a default 12-word BIP-39 recovery phrase:

```bash
pwgen2 -m
```

Create a 24-word BIP-39 recovery phrase:

```bash
pwgen2 -m 24
```

Create a mnemonic as JSON:

```bash
pwgen2 -m -j
```

Mnemonic mode is mutually exclusive with password generation, custom symbol sets, and hash options.

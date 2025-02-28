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

## Installation

```bash
cargo install pwgen2
```

## Usage

```text
Usage: pwgen2 [OPTIONS] [length] [number]

Arguments:
  [length]  password length [default: 18]
  [number]  Number of passwords to generate [default: 1]

Options:
  -p, --pin           Generate a pin
  -a, --alphanumeric  Generate an alphanumeric password
  -h, --help          Print help
  -V, --version       Print version
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

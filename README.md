# EatPdb

[![.NET Core](https://github.com/codehz/EatPdb/workflows/.NET%20Core/badge.svg?branch=master)](https://github.com/codehz/EatPdb/actions/)

Export all symbols of PE file in pdb file, so you can easily import them.

Only support x86_64 for now.

## Usage

You need a config file to describe the filter

```bash
eatpdb exec config.yaml
```

config.yaml:

```yaml
in: your.exe
out: your_mod.exe
filterdb: extra.db
filter: !blacklist
  - prefix: "_"
  - prefix: "?__"
  - prefix: "??_"
  - prefix: "??@"
  - prefix: "?$TSS"
  - regex: "std@@[QU]"
  - name: "atexit"
```

## LICENSE

MIT

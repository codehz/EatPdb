# EatPdb

[![.NET Core](https://github.com/codehz/EatPdb/workflows/.NET%20Core/badge.svg?branch=master)](https://github.com/codehz/EatPdb/actions/)

Export all symbols of PE file in pdb file, so you can easily import them.

Only support x86_64 for now.

## Usage

```
eatpdb -i your.exe -o your_mod.exe -p your.pdb --DllName your_mod.exe
```

## LICENSE

MIT
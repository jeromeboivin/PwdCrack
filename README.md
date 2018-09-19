# PwdCrack

Simple password recovery utility, written in C#. Only SHA-512 hashed passwords are supported for now.

## Usage

```
PwdCrack <dictionary/hash>
PwdCrack -h <hashfile>
```

### Brute-force with dictionary

```
PwdCrack.exe -b <min chars> <max chars> <hashfile> <dictionary>
```

Edit _BruteForceCharacterSet_ key in PwdCrack.exe.config to change character set.

Available values:
* All
* AlphaMixedWithNumbersAndCommonSymbols
* Numbers
* NumbersAndSymbols
* NumbersAndCommonSymbols
* AlphaUpper
* AlphaUpperWithNumbers
* AlphaLower
* AlphaLowerWithNumbers
* AlphaMixed
* AlphaMixedWithNumbers
* CommonSymbols
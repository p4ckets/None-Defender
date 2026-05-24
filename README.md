# Kiln

Wraps any Nuitka-compiled Python binary in an RC4-encrypted C dropper that
defeats Defender's static ML detection. Drop-in for any project -- no changes
to your source required.

---

## Requirements

- Python 3.10+  (`py` launcher)
- Nuitka:  `py -m pip install nuitka`
- VS 2022 / MSVC 14.42  (paths in `build.bat` -- edit to match your install)
- Windows SDK 10.0.26100.0

---

## Quickstart

```
build.bat <entry.py> [OutputName] [extra nuitka flags]
```

```
build.bat myapp\main.py MyApp
```

Outputs `myapp\payload.exe`.  The intermediate `MyApp.exe` is deleted.

Pass extra Nuitka flags as the third argument:

```
build.bat myapp\main.py MyApp --include-package=requests --include-package=crypto
```

---

## What it does

**prebuild** -- before Nuitka runs, 64 cryptographically random bytes get
injected into `OnefileBootstrap.c` as a `.CRT$XCU` constructor. Forces a
compiler cache miss so the extracted binary inside the cache dir has a new
hash every single build. Bearfoos.B!ml and similar static ML detections
fingerprint that binary -- now they can't.

A random Python junk module (`_jnk.py`) is also injected and imported from
your entry point. Unique bytecode every build.

**pack** -- RC4-encrypts the Nuitka binary with a 32-byte random key. A C
stub embeds the ciphertext as a PE RCDATA resource. All Windows API calls in
the stub are resolved at runtime via PEB walk -- no IAT. Strings are XOR-
encoded in the binary.

At runtime the stub decrypts the payload in memory, then re-mangles it
(random section names, randomised timestamp, zeroed checksum, randomised DOS
stub) before writing it to disk. Every execution produces a different file on
disk. Signature rules can't track it.

---

## Got detected? Just rebuild

```
build.bat <entry.py> [OutputName]
```

No code changes needed. The randomisation is automatic

---

## Using pack.py directly

```
py pack.py prebuild main.py
py pack.py pack MyApp.exe payload.exe
```

`prebuild` takes an entry point and patches `OnefileBootstrap.c` + generates
the junk module.

`pack` takes the Nuitka output exe and writes a packed `payload.exe`.

---

## Disclaimer
This tool is for educational and authorized testing purposes only. Use only in controlled environments with proper consent.

## File layout

```
Kiln\
  build.bat   -- orchestrates prebuild -> nuitka -> pack
  pack.py     -- prebuild and pack subcommands
  README.md
```

# Media For Tamper-Averse Humans (MFTAH)
C3 library for creating and manipulating [MFTAH](https://github.com/NotsoanoNimus/MFTAH)-encrypted data payloads, both static and streamed types.

![image](https://github.com/user-attachments/assets/016a21a3-b8f7-4517-9501-2f84e84b3c0b)


## Usage
For any C3 project which aims to incorporate this format, simply clone the repo to the project's `lib/` folder, `import mftah;`, and you're off.

Some key uses:
  - `mftah::new` and `mftah::decrypt`: Encrypt and Decrypt fixed-length MFTAH payloads from a heap-allocated pointer.
    - This requires copying the full breadth of the input data into RAM before operating on it, so be careful with large inputs!
  - `mftah::stream_new` and `mftah::stream_decrypt`: Encrypt and Decrypt streamed MFTAH payloads.
    - This chunks the input data into blocks and streams (or "yields") the result of each block operation one at a time, which is much more memory-efficient.
    - Streaming is very useful for a very large input data pool, for memory-constrained systems, or for operating with other block-based applications (such as `dd`).


## Why
See my write-up about MFTAH on my personal site: **TODO: LINK when written**

In short, MFTAH is a _file format_ which encapsulates a "payload" of generic data. This data can be anything from a bootable OS image, to a JPEG image, to a simple "hello, world!" string.

The means to retrieve that payload are securely set in the file format's header, and dedicated MFTAH-based applications are used to extract the payload.

This generic encapsulation of data allows MFTAH to be a one-of-many step in an existing pipeline of securing data. For example:

```text
SECURED IN-MEMORY DATA ==> TAR ==> GZIP ==> MFTAH ==> DISK
```

This pipeline incorporates MFTAH just before writing the compressed data to the disk, ensuring that only protected data is ever stored.

As expected, it's just as easy to get your data back out of its encrypted format by reversing this pipeline:
```text
DISK ==> MFTAH ==> GZIP ==> TAR ==> ORIGINAL DATA
```


## Project-specific Details
Aside from being written in [the remarkably fun C3 language](https://c3-lang.org/), this library has some quirks that are worth mentioning explicitly.

### Design Goals & Decisions
`mftah.c3l` is designed to be included in any generic application. Most importantly, this includes ***runtime environments outside of LIBC*** - such as custom operating system applications, UEFI applications, etc.

### Fixed Dependencies
To the absolute extent that is possible, this is a _self-contained_ library, meaning dependencies are ideally fixed and are not dynamically sourced.

While this has caveats - such as not receiving security or functionality updates regularly and automatically - it allows the library to flexibly customize and tailor different algorithms and constructs to its needs.

Such a need _mostly_ consists of ripping out any `stdlib` or `libc` references where possible, so users of the library can provide their own `malloc` symbol, `realloc`, `memcpy`, etc.

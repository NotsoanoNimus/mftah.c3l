# Media For Tamper-Averse Humans (MFTAH)
C3 library for creating and manipulating [MFTAH](https://github.com/NotsoanoNimus/MFTAH)-encrypted data payloads, both static and streamed types.


## Usage
For any C3 project which aims to incorporate this format, simply clone the repo to the project's `lib/` folder, `import mftah;`, and you're off.

Some key uses:
  - `mftah::new` and `mftah::decrypt`: Encrypt and Decrypt static MFTAH payloads. This copies the full breadth of an input into RAM before operating on it, so be careful with large payloads!
  - `mftah::stream_new` and `mftah::stream_decrypt`: Encrypt and Decrypt streamed MFTAH payloads. This chunks the input data into blocks and streams the result of each block operation one at a time, which is much more memory-efficient.


## Why
See my write-up about MFTAH on my personal site: **TODO: LINK when written**

In short, MFTAH is a _file format_ which encapsulates a "payload" of generic data. This data can be anything from a bootable OS image, to a JPEG image, to a simple "hello, world!" string.

The means to retrieve that payload are securely set in the file format's header, and dedicated MFTAH-based applications are used to extract the payload.

This generic encapsulation of data allows MFTAH to be a one-of-many step in an existing pipeline of securing data. For example:

```text
SECURED IN-MEMORY DATA ==> TAR ==> GZIP ==> MFTAH ==> DISK
```

This pipeline incorporates MFTAH just before writing the compressed data to the disk, ensuring that only protected data is ever stored.


## File Format
**TODO**: Insert a specification reference for the MFTAH file format (both streamed payloads and ordinary payloads).


## Project-specific Details
Aside from being written in [the up-and-coming C3 language](https://c3-lang.org/), this library has some quirks that are worth mentioning explicitly.

### Design Goals & Decisions
`mftah.c3l` is designed to be included in any generic application. Most importantly, this includes ***runtime environments outside of LIBC*** - such as custom operating system applications, UEFI applications, etc.

### Fixed Dependencies
To the absolute extent that is possible, this is a _self-contained_ library, meaning dependencies are ideally fixed and are not dynamically sourced.

While this has caveats - such as not receiving security or functionality updates regularly and automatically - it allows the library to flexibly customize and tailor different algorithms and constructs to its needs.

Such a need _mostly_ consists of just ripping out any `stdlib` or `libc` references where possible, in favor of the `HooksTable` construct which provides analogous functionality.

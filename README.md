<div align="center">
  <img src="./brovan_banner.png" alt="Brovan banner" />

# Brovan

*"Emulate like a bro"* - *for your emulation services.*

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square)](https://dotnet.microsoft.com/)
[![Language](https://img.shields.io/badge/language-C%23-239120?style=flat-square)](https://learn.microsoft.com/dotnet/csharp/)

</div>

Brovan is a C# user-mode binary emulator for inspecting and running x86/x64 programs in a controlled emulated environment. It supports PE, ELF, memory dumps, and raw files with no recognized file format.

It is useful for malware analysis, reverse engineering, debugging binaries, or generally understanding what a program is doing, without executing their instructions directly on the host CPU.

## Why Brovan?

Brovan gives you a hands-on way to load a binary, observe what it does, and fully control execution from an interactive shell.

You can use it to:

* analyze suspicious Windows binaries
* inspect PE headers, sections, imports, exports, functions, and strings
* step through emulated code instruction by instruction
* trace syscall behavior
* monitor function calls
* inspect and patch memory
* set breakpoints and watchpoints
* snapshot emulator state and restore it later
* test how binaries interact with files, registry state, memory, threads, networking, and other user-mode objects
* Fully control the process, even file descriptor for linux or handles for windows can be fully controlled, duplicated, or it's properties modified directly from the emulation menu.

## What Brovan offers

* PE, ELF, and .NET binary parsing support
* Windows user-mode PE emulation
* Linux/ELF guest support for common syscall flows
* syscall modeling for many Windows user-mode paths and linux user paths, but more will be worked on
* generic raw binary/blob loading with the guest of your choice
* interactive debugger-style command shell
* memory regions, hexdumps, disassembly, and string search
* breakpoints and read/write/fetch watchpoints
* snapshots and restore support
* syscall tracing and syscall rules to set custom behavior for syscalls (or even add unsupported ones yourself without adding it directly to the code, but to a certain limit)
* function monitoring with argument decoding
* configurable host networking policy for emulated networking devices

## Requirements for builds

* .NET 8 SDK
* x64 runtime environment
* `unicorn.dll`/`libunicorn.so` available under `Resources/`
* Windows is recommended for the primary Windows PE emulation workflow

Visual Studio Build Tools are useful on Windows because Brovan can use `editbin` when available because it disables CFG, as unicorn wouldn't work without it because of how the JIT works.

If Brovan detected that Control Flow Guard are still running, it will automatically restart the process with CFG disabled, so even if you don't have the `editbin` you are still good.

## Build

```bash
dotnet build -c Release
```

The release output is created under:

```text
bin/Release/net8.0/
```

## Usage

```bash
Brovan [options] <path-to-binary> [program arguments...]
```

Examples:

```bash
Brovan sample.elf
Brovan --quick sample.exe
Brovan --quick -c "start;run" sample.exe
Brovan --net=none sample.elf
```

Brovan options must come before the target binary path. Anything after the binary path is passed to the emulated program.

## CLI options

| Option             | Description                                                                |
| ------------------ | -------------------------------------------------------------------------- |
| `-q`, `--quick`    | Start faster and use less memory by skipping deeper static analysis.       |
| `-s`, `--silent`   | Only show stdout from the emulated program.                                |
| `-c`, `--command`  | Run interactive commands automatically, separated by `;`.                  |
| `--net <mode>`     | Set networking policy: `none`, `loopback`, or `full`. Default: `loopback`. |
| `--net-allow <ip>` | Allow a specific IPv4 or IPv6 address.                                     |
| `-h`, `--help`     | Show help.                                                                 |

## Interactive shell

Brovan includes an interactive debugger-style shell for controlling execution and inspecting state.

Some common (but not all) commands include:

| Command                    | Description                          |
| -------------------------- | ------------------------------------ |
| `start`                    | Initialize the emulator.             |
| `run`                      | Run execution through the scheduler. |
| `continue` / `c`           | Resume execution.                    |
| `step`                     | Execute one instruction.             |
| `stepover`                 | Step over a call instruction.        |
| `dumpregs`                 | Show register state.                 |
| `hexdump <address> <size>` | Dump memory.                         |
| `disasm <address> <size>`  | Disassemble memory.                  |
| `regions`                  | List mapped memory regions.          |
| `modules`                  | List loaded modules.                 |
| `findstr`                  | Search memory for strings.           |
| `bp`                       | Manage breakpoints.                  |
| `watch`                    | Manage watchpoints.                  |
| `snap` / `restore`         | Save or restore emulator state.      |
| `bininfo`                  | Show parsed binary information.      |
| `syscall`                  | Trace or control syscall behavior.   |
| `funcmon`                  | Monitor function calls.              |
| `help [command]`           | Show help.                           |

Example:

```bash
Brovan --quick -c "start;showinstrs;run" sample.exe
```

## Malware analysis note

Brovan can help analyze malware and suspicious binaries by emulating user-mode execution and exposing runtime behavior. It is still important to handle unknown files carefully.

Brovan is not a replacement for a properly isolated malware lab or VM. Treat samples as hostile and use normal reverse-engineering precautions.

Brovan does not let the emulated program directly write to the real host filesystem, Guest-side writes are redirected into Brovan's virtual filesystem model instead.

But reads are different, if the guest binary and host environment are compatible, Brovan exposes the host files for read-only as it is required to run the program in the most compatible state, the program might need stuff such as windows libraries and other runtime files needed for emulation, which might expose you to data exfiltration malware, such as info stealers. However, this happens only if the binary and the host OS is compatible. if not, file access generally falls back to Brovan's virtual filesystem model instead for both read and writes.

Network access is controlled by policy. The default mode is `loopback`, but running with `--net=full` allows full network behavior with no restrictions. For malware, that can include data exfiltration if the sample reaches supported network devices implemented by the emulator. Use `--net=none` when analyzing unknown samples unless network behavior is intentionally being studied.

# Dependencies used
Thanks to <a href="https://github.com/icedland/iced">Iced library</a> for x86_64 disassembly and assembly.

Thanks to <a href="https://github.com/unicorn-engine/unicorn">Unicorn Engine</a> for the core emulator.

# Credits
Thanks to my friend <a href="https://github.com/GittingHubbers">GittingHubbers</a> for help with the MLFQ Scheduler.

# License
This software is licensed under GPL-2.0.

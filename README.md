<div align="center">
  <img src="./brovan_banner.png" alt="Brovan banner" />

# Brovan

*"Emulate like a bro"* - *for your emulation services.*

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square)](https://dotnet.microsoft.com/)
[![Language](https://img.shields.io/badge/language-C%23-239120?style=flat-square)](https://learn.microsoft.com/dotnet/csharp/)

</div>

Brovan is a powerful user-mode binary emulator for inspecting and running x86_64 programs in a controlled emulated environment. It supports PE, ELF, memory dumps, and even raw files with no recognized file format.

It is a tool used to analyze binaries in an interactive way and discovering what functions they are trying to access, what they are doing, and fully controlling the program inside the emulator.

it is useful for malware analysis, reverse engineering, debugging binaries, or generally understanding what a program is doing, without executing their instructions directly on the host CPU.

## Core Features

<div align="center">

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🖥️ Multi-format loading</h3>
      <p>Run <b>PE</b>, <b>ELF</b>, memory dumps, and even raw binaries with no recognized file format.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🧠 Interactive analysis</h3>
      <p>Inspect execution live, follow control flow, and understand what a program is doing as it runs.</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🔎 Syscall & function tracing</h3>
      <p>See which APIs, syscalls, and functions the target resolves and accesses inside the emulator.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🛡️ Controlled execution</h3>
      <p>Emulate binaries in a safe sandbox environment without executing them directly on the host CPU.</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🌐 Network traffic dumping</h3>
      <p>Capture and inspect emulated network activity to better understand program behavior.</p>
    </td>
    <td width="50%" valign="top">
      <h3>⚙️ Reverse-engineering friendly</h3>
      <p>Useful for malware analysis, debugging, and general binary inspection workflows.</p>
    </td>
  </tr>
</table>

</div>

<div align="center">
  <p><strong>And much more ✨</strong></p>
</div>

## Preview

<div align="center">
  <table style="border-collapse: separate; border-spacing: 12px 10px;">
    <tr>
      <td align="center">
        <a href="https://github.com/user-attachments/assets/d77b4d0a-6715-4e97-ac0b-f37ef23e37bd">
          <img src="https://github.com/user-attachments/assets/d77b4d0a-6715-4e97-ac0b-f37ef23e37bd"
               alt="Brovan preview 1" width="270"
               style="border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.18);" />
        </a>
        <br /><sub><i>Emulating linux binary (fastfetch) on Windows</i></sub>
      </td>
      <td align="center">
        <a href="https://github.com/user-attachments/assets/4c264450-e7bd-48ab-85e0-4220ae416c88">
          <img src="https://github.com/user-attachments/assets/4c264450-e7bd-48ab-85e0-4220ae416c88"
               alt="Brovan preview 2" width="270"
               style="border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.18);" />
        </a>
        <br /><sub><i>Showing syscalls and functions the binary accesses</i></sub>
      </td>
      <td align="center">
        <a href="https://github.com/user-attachments/assets/a3f41dda-fe36-48a9-9ea2-f02b24235d7d">
          <img src="https://github.com/user-attachments/assets/a3f41dda-fe36-48a9-9ea2-f02b24235d7d"
               alt="Brovan preview 3" width="270"
               style="border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.18);" />
        </a>
        <br /><sub><i>Running raw/unrecognized binaries directly</i></sub>
      </td>
    </tr>
    <tr>
      <td colspan="3" align="center">
        <a href="https://github.com/user-attachments/assets/d0932ff6-08cf-49e5-a48d-70c577352152">
          <img src="https://github.com/user-attachments/assets/d0932ff6-08cf-49e5-a48d-70c577352152"
               alt="Brovan preview 4" width="270"
               style="border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.18);" />
        </a>
        &nbsp;&nbsp;&nbsp;
        <a href="https://github.com/user-attachments/assets/8bea785c-8f29-4261-8450-97e6b9dd7622">
          <img src="https://github.com/user-attachments/assets/8bea785c-8f29-4261-8450-97e6b9dd7622"
               alt="Brovan preview 5" width="270"
               style="border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.18);" />
        </a>
        <br /><sub><i>Dumping emulated network traffic &amp; viewing them</i></sub>
      </td>
    </tr>
  </table>
</div>

## Documentation

The wiki is the main source for:

- Build instructions
- Architecture overview
- Usage guide (recommended, as Brovan have a lot than it advertises and some other useful functionalities)
- Command reference

See the wiki here: https://github.com/AdvDebug/Brovan/wiki

> [!WARNING]
> The [Releases](https://github.com/AdvDebug/Brovan/releases) page may not always have the latest changes.  
> For the most up-to-date version, **[build from source](https://github.com/AdvDebug/Brovan/wiki/Building-Brovan)** instead.

# Credits
Thanks to <a href="https://github.com/icedland/iced">Iced library</a> for x86_64 disassembly and assembly.

Thanks to <a href="https://github.com/unicorn-engine/unicorn">Unicorn Engine</a> for the core emulator.

Thanks to my friend <a href="https://github.com/GittingHubbers">GittingHubbers</a> for help with the MLFQ Scheduler.

# License
This software is licensed under GPL-2.0.

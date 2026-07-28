<div align="center">
  <img src="./brovan_banner.png" alt="Brovan banner" width="100%" style="border-radius: 10px;" />
  
  <br/><br/>
  
  [![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
  [![Language](https://img.shields.io/badge/Language-C%23-239120?style=flat-square&logo=csharp)](https://learn.microsoft.com/dotnet/csharp/)
  [![License](https://img.shields.io/badge/License-GPL--2.0-blue?style=flat-square)](https://www.gnu.org/licenses/gpl-2.0.html)
  
  <p align="center">
    <b>A user-mode x86_64 binary emulator for inspecting programs, tracing syscalls, and safely running untrusted software.</b>
  </p>
  
</div>

## What is Brovan?

Brovan is an interactive x86_64 emulator that gives you full control over how programs execute. It can be used to reverse engineer binaries, trace API and system calls, capture network traffic, or run software in an isolated environment without executing it directly on your host CPU.

It is designed to support as much software as possible while remaining a safe, efficient, and high-performance option for running software across Windows and Linux. Brovan is still in early development, so it is not yet fully mature or reliable.

Supported backends:
* **Unicorn Engine** for cross-platform emulation
* **WHP** (Windows Hypervisor Platform) for hardware acceleration on Windows
* **KVM** (Kernel-based Virtual Machine) for hardware acceleration on Linux

## Core Features

<div align="center">

<table width="100%">
  <tr>
    <td width="50%" valign="top" align="left">
      <p><b>MULTI-FORMAT LOADING</b></p>
      <p>Load and execute binaries directly inside the emulator without host installation.</p>
      <sub><code>PE</code> &nbsp; <code>ELF</code> &nbsp; <code>Memory Dumps</code> &nbsp; <code>Raw Shellcode</code></sub>
    </td>
    <td width="50%" valign="top" align="left">
      <p><b>BROVVULK GRAPHICS LAYER</b></p>
      <p>Custom Vulkan translation subsystem handling DXVK calls and game rendering.</p>
      <sub><code>DXVK</code> &nbsp; <code>DirectX</code> &nbsp; <code>Vulkan Surface</code></sub>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top" align="left">
      <p><b>SYSCALL & API TRACING</b></p>
      <p>Inspect execution live to see what functions, DLLs, and kernel calls the program accesses.</p>
      <sub><code>Kernel Syscalls</code> &nbsp; <code>Symbol Resolving</code> &nbsp; <code>Loaded DLLs</code></sub>
    </td>
    <td width="50%" valign="top" align="left">
      <p><b>NETWORK DUMPING</b></p>
      <p>Intercept guest socket traffic and export network activity for payload analysis.</p>
      <sub><code>Socket Intercept</code> &nbsp; <code>PCAP Capture</code> &nbsp; <code>Traffic Analysis</code></sub>
    </td>
  </tr>
</table>

</div>

## Previews & Demos

### Gaming & Graphics (Brovvulk)

Brovan can render guest graphical applications through its Brovvulk translation subsystem. Here is a sample game i had (Deltarune), but it can work on many other games:

<div align="center">

<table width="100%">
  <tr>
    <td align="center" width="60%">
      <a href="https://github.com/user-attachments/assets/d77b4d0a-6715-4e97-ac0b-f37ef23e37bd">
        <img src="https://github.com/user-attachments/assets/15f11fe6-4f6b-4df1-a568-8be26d1e00d7" 
             alt="Deltarune running in Brovan" width="100%" 
             style="border-radius: 8px; border: 1px solid #30363d;" />
      </a>
    </td>
    <td valign="top" width="40%" align="left">
      <h4>Deltarune Bring-up</h4>
      <ul>
        <li>Vulkan surface rendering via Brovvulk</li>
        <li>DPI-aware host window integration</li>
        <li>WHP acceleration for a smoother gaming experience</li>
      </ul>
    </td>
  </tr>
</table>

</div>

### Binary Execution & Tracing

<div align="center">

<table width="100%">
  <tr>
    <td width="33%" align="center" valign="top">
      <a href="https://github.com/user-attachments/assets/d77b4d0a-6715-4e97-ac0b-f37ef23e37bd">
        <img src="https://github.com/user-attachments/assets/d77b4d0a-6715-4e97-ac0b-f37ef23e37bd" 
             alt="Cross-platform Linux execution" width="100%" style="border-radius: 6px;" />
      </a>
      <br />
      <b>Linux ELF on Windows</b>
      <br />
      <sub>Running <code>fastfetch</code> cross-platform</sub>
    </td>
    <td width="33%" align="center" valign="top">
      <a href="https://github.com/user-attachments/assets/4c264450-e7bd-48ab-85e0-4220ae416c88">
        <img src="https://github.com/user-attachments/assets/4c264450-e7bd-48ab-85e0-4220ae416c88" 
             alt="Syscall tracing log" width="100%" style="border-radius: 6px;" />
      </a>
      <br />
      <b>Syscall Tracing</b>
      <br />
      <sub>Live logs of API calls and dynamic symbols</sub>
    </td>
    <td width="33%" align="center" valign="top">
      <a href="https://github.com/user-attachments/assets/a3f41dda-fe36-48a9-9ea2-f02b24235d7d">
        <img src="https://github.com/user-attachments/assets/a3f41dda-fe36-48a9-9ea2-f02b24235d7d" 
             alt="Raw binary execution" width="100%" style="border-radius: 6px;" />
      </a>
      <br />
      <b>Raw Binaries</b>
      <br />
      <sub>Executing shellcode and memory dumps</sub>
    </td>
  </tr>
</table>

</div>

### Network Inspection

<div align="center">

<table width="100%">
  <tr>
    <td width="50%" align="center" valign="top">
      <a href="https://github.com/user-attachments/assets/d0932ff6-08cf-49e5-a48d-70c577352152">
        <img src="https://github.com/user-attachments/assets/d0932ff6-08cf-49e5-a48d-70c577352152" 
             alt="Network dumping" width="100%" style="border-radius: 6px;" />
      </a>
      <br />
      <b>Network Capture</b>
      <br />
      <sub>Intercepting guest socket reads and writes</sub>
    </td>
    <td width="50%" align="center" valign="top">
      <a href="https://github.com/user-attachments/assets/8bea785c-8f29-4261-8450-97e6b9dd7622">
        <img src="https://github.com/user-attachments/assets/8bea785c-8f29-4261-8450-97e6b9dd7622" 
             alt="Traffic viewer" width="100%" style="border-radius: 6px;" />
      </a>
      <br />
      <b>Traffic Analyzer</b>
      <br />
      <sub>Viewing dumped PCAPs and payloads</sub>
    </td>
  </tr>
</table>

</div>

## Documentation & Wiki

Check out the [GitHub Wiki](https://github.com/AdvDebug/Brovan/wiki) for:
- [Building from source](https://github.com/AdvDebug/Brovan/wiki/Building-Brovan)
- Architecture details
- Command reference and usage guides
- [FAQ](https://github.com/AdvDebug/Brovan/blob/main/FAQ.md)

> [!WARNING]
> The [Releases](https://github.com/AdvDebug/Brovan/releases) page may not always have the latest changes.  
> For the most up-to-date version, **[build from source](https://github.com/AdvDebug/Brovan/wiki/Building-Brovan)** instead
> or use the latest build from <a href="https://github.com/AdvDebug/Brovan/actions">GitHub Actions</a>

# Credits
Thanks to <a href="https://github.com/icedland/iced">Iced library</a> for x86_64 disassembly and assembly.

Thanks to <a href="https://github.com/unicorn-engine/unicorn">Unicorn Engine</a> for the core emulator.

Thanks to my friend <a href="https://github.com/GittingHubbers">GittingHubbers</a> for help with the MLFQ Scheduler.

## Credits

- [Iced](https://github.com/icedland/iced) for x86_64 disassembly/assembly.
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn) for core CPU emulation.
- Thanks to [GittingHubbers](https://github.com/GittingHubbers) for help with the MLFQ scheduler.

## License

GPL-2.0

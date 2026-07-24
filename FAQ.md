# FAQ
A collection of questions that come up often, with answers to save you some digging.

## Questions

<details>
<summary><b>Why not just use a VM or QEMU?</b></summary>

---

QEMU and VMs in general are great for running software in a realistic environment, but that also means you are often at the mercy of the kernel and the rest of the system underneath it.

For example, in Brovan you can silently intercept and log every memory read of a specific variable without modifying the binary, patching page tables, or triggering any signal the target process could detect directly. something fundamentally impossible in a real kernel or main-stream VMs, where any attempt to trap such accesses would require invasive kernel changes or debug registers visible to the program.

Also full kernel emulation is especially expensive, both in performance and in implementation complexity. A lot of low-level behavior has to be modeled just to keep the system running, even when the analysis does not need all of it.

Brovan is designed around analysis, observability, and control. It also aims to stay efficient by reducing allocations and using stack allocations where possible, it might not be perfect everywhere since the project is being built and maintained by one person.

The goal is to make it easier to inspect, modify, and instrument execution for reverse engineering, malware analysis, and binary research.

**In short:**
- Use QEMU or a VM when you want a general-purpose environment to run software.
- Use Brovan when you want deep visibility, fine-grained control, and analysis-first workflows.

</details>

<details>
<summary><b>What makes Brovan different from projects like Qiling, Binee, UnicornPE?</b></summary>

---

Brovan and other projects like Qiling have very different design goals.

Qiling is written in Python and operates primarily at the Windows API level. This makes it very flexible for scripting and rapid prototyping, but it also means every Windows API function that software depends on has to be reimplemented. Maintaining accurate behavior across thousands of APIs is a significant challenge, and missing or incomplete implementations can lead to compatibility issues, along with essential but missing features.

Brovan takes a different approach. Instead of emulating the Windows API, it operates at the system call level. It loads the host system's native Windows libraries into the emulated process and lets those libraries perform process initialization and API functionality. This greatly reduces the amount of code that needs to be maintained while providing behavior that is much closer to a real Windows environment, since the emulator is using the same libraries installed on your system. It focuses on guest syscall handling, process startup, thread/TEB setup, and module loading. On Windows, it can load native modules such as ntdll.dll and resolve core startup routines from them, which keeps guest behavior closer to how a real system boots a process.

This design allows development to focus primarily on correctly implementing the kernel interface (system calls) rather than recreating the behavior of every exported function in every DLL. The result is higher compatibility, less duplicated code, and fewer opportunities for API implementation bugs.

Brovan also targets both Windows PE and Linux ELF binaries, making it a flexible foundation for emulation that is designed around direct guest execution rather than a scripting-first abstraction.

Ultimately, the two projects target different use cases. Qiling is an excellent choice if you need a mature scripting and instrumentation framework. Brovan is designed for users who prioritize performance, compatibility, and faithful emulation with minimal reimplementation of Windows internals, as you also have an interactive menu to emulate from which makes it user-friendly.

</details>

<details>
<summary><b>How does Brovan enforce sandboxing?</b></summary>

---

Brovan is designed so that emulated binaries have very limited interaction with the host system.

At a high level, the primary way a binary can interact with the host is through file access. Networking is disabled except for loopback connections by default, and network access is controlled explicitly through the `--net` command-line argument.

**For filesystem access:**
* Write operations are always redirected and isolated from the host filesystem.
* Path traversal attempts are blocked.
* Symlink-based escapes are prevented.
* Direct writes to host files are not permitted.
* Windows cannot access linux's VFS and vice versa.
* Terminal output is filtered using the `LightEscaped` option, which blocks potentially dangerous console control sequences while allowing safe text styling and ANSI escape sequences.

Read access is more permissive, but only when the host environment is compatible with the emulated binary. When compatibility requirements are not met, filesystem operations generally fall back to Brovan's VirtualFS implementation instead.

This design allows software to access the resources it needs while reducing the risk of unintended modification of the host system and maintaining a controlled analysis environment.

</details>

<details>
<summary><b>What's up with Brovan and Control Flow Guard?</b></summary>

---

As most of unicorn users would know, the emulator's JIT (TCG) doesn't support CFG because of the way it jumps to the generated code, which is incompatible with the mitigation.

Currently unicorn doesn't have a fix, and looks like it won't come any time soon, as looks like they have other issues in the engine that they want to take care of.

All unicorn programs running on windows, if they need to do anything real with unicorn, it needs to disable CFG. not just Brovan. this is usually done via the project settings and isn't ever mentioned, but the reason it is mentioned in Brovan is because the .NET Compiler doesn't support controlling the linker directly, so it is mentioned so people are aware.

The post-build automatically disables it when building for Windows via a custom code task, it can also restart the process with the mitigation disabled if the task failed during compilation.

</details>

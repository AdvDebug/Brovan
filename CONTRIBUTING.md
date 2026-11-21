<div align="center">

# Contributing to Brovan

Thanks for helping. Contributions of every size are welcome, and you do not need to be an expert.

[README](README.md) &nbsp;·&nbsp; [Wiki](https://github.com/AdvDebug/Brovan/wiki) &nbsp;·&nbsp; [Open an issue](https://github.com/AdvDebug/Brovan/issues)

</div>

## Ways to help

| Area | What you can do |
|---|---|
| **Test and report bugs** | Run games and programs, and open an issue when one breaks. A clear report is one of the most useful things you can send. |
| **Implement system calls** | The most important work. Add missing system calls, fill in the cases programs expect, and make results and error codes match real Windows. |
| **Improve compatibility** | Pick a program that does not run yet and find out why. The wiki's [troubleshooting guide](https://github.com/AdvDebug/Brovan/wiki/Debugging-&-Troubleshooting) shows how. |
| **Make it faster** | Find bottlenecks in the scheduler, in system calls that run often, in registry reads and similar hot paths. |
| **Improve the debugger** | Make the debugger prompt and its output easier to read and follow. |
| **Improve the docs** | Fix or extend the README, the FAQ and the wiki. |

## Before you start

- Read the wiki's [architecture page](https://github.com/AdvDebug/Brovan/wiki/Architecture) to see how Brovan fits together.
- For anything bigger than a small fix, open an issue first, so we can agree on the approach before you spend time on it.

## Build and test

You need the .NET 10 SDK, CMake and a C++ compiler. The wiki's [build page](https://github.com/AdvDebug/Brovan/wiki/Building-Brovan) lists the requirements and the optional OpenGL and OpenCL drivers.

```powershell
dotnet build Brovan/Brovan.csproj -c Release
```

> [!TIP]
> On Windows, build from PowerShell or Command Prompt, not Git Bash. The Unicorn step extracts an archive with `tar`, and the `tar` in Git Bash cannot handle Windows paths.

Then run a program with your build, from `Brovan/bin/Release/net10.0`:

```powershell
.\Brovan.exe --backend=whp -c "start;exit" C:\path\to\program.exe
```

On Windows, the first start asks for administrator rights once, to copy the registry. Test on Windows Hypervisor Platform and on Unicorn (`--backend=unicorn`) if you can, since some bugs show up on only one of them. Comparing with what the program does on real Windows helps too.

## Pull requests

1. Fork the repository and create a branch for your change.
2. Make the change and test it as well as you can.
3. Open a pull request that explains what changed, why, and how to test it.

Keep each pull request to one change. Several small ones are much easier to review than one big one. If it fixes a bug, say how to reproduce the bug before the fix and how to check it after. If you could not test something, that is fine. Just say what you tested and what still needs checking.

**Code style.** Match the file you are editing, including its naming and its summaries. Keep changes small and readable, use clear names, and do not add complexity unless it solves a real problem.

**Commit messages.** Use a short subject that says what the change does, under about 50 characters, such as "Duplicate handles into other session processes".

## Reporting bugs

Use the [bug report template](https://github.com/AdvDebug/Brovan/issues/new?template=bug_report.md) and include:

- the program, what you were trying to do, and what happened instead
- the steps to reproduce it
- your OS and the backend you used
- `error_log.log` from the folder next to Brovan if it crashed, and a screenshot if it helps

## Questions

If something is unclear, open an issue. It is fine to ask before you start a pull request. You can also contact me on Discord if you want to ask privately.

Thank you. Every contribution makes Brovan better.

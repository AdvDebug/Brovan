# Ideas

In this file I will mention some ideas, some bugs to fix, and implementations for anyone looking to contribute.

But in a nutshell, the main ways to help would be to add more syscalls with correct implementations, improve visualizations, and improving compatibility with other programs.

Anything that comes to mind will be added here.

## Syscall implementations (most important for the project)

* Add more syscall implementations.
* Fill in missing cases that programs expect during normal execution.
* Make syscall results and error codes behave closer to Linux.
* Handle argument validation more carefully.
* Improve edge cases where the emulator currently returns an unsupported or incomplete result.

and generally improve compatibility with programs.

## Visualization improvements

* Improve the visualizations.
* Make the emulation menu easier to read while commands are being typed.
* Distinguish between plain text, valid commands, and expressions the processor can compute.
* Make output formatting clearer for debugging and state inspection.
* Improve how information is presented so it is easier to follow during emulation.

## Performance improvements

Finding any bottlenecks or improvements in the emulator. that might be in the scheduler, a hot syscall (a syscall that is called frequently) that could be optimized, registry reading, etc.

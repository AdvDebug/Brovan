# Ideas

In this file I will mention some ideas, some bugs to fix, and implementations for anyone looking to contribute.

But in a nutshell, the main ways to help would be to add more syscalls with correct implementations, improve visualizations, and improving compatibility with other programs.

## Syscall implementations (most important for the project)

* Add more syscall implementations.
* Fill in missing cases that programs expect during normal execution.
* Make syscall results and error codes behave closer to Linux.
* Handle argument validation more carefully.
* Improve edge cases where the emulator currently returns an unsupported or incomplete result.

and generally improve compatbility with programs.

## Visualization improvements

* Improve the visualizations.
* Make the emulation menu easier to read while commands are being typed.
* Distinguish between plain text, valid commands, and expressions the processor can compute.
* Make output formatting clearer for debugging and state inspection.
* Improve how information is presented so it is easier to follow during emulation.

## Linux symlink handling

Symlinks are currently handled in a bad way: instead of being handled as symlinks, the file is copied to the symlink location.

* Handle Linux symlink files inside `GeneralHelper.cs` properly.
* Keep the symlink target instead of copying the file contents.
* Support symlink targets as real paths.
* Make sure path resolution follows symlinks correctly.
* Avoid losing the fact that a path is a symlink.
* Avoid bad behavior when symlinks point to other symlinks or form a loop.

This causes the Linux folder to be large in size while it is much smaller.

## Performance improvements

Finding any bottlenecks or improvements in the emulator.

## Bug in the scheduler

Right now there's multiple bugs in the MLFQ scheduler that causes some multi-threaded windows programs to exit early or hang. Most of these issues are fixed, but some might still be lurking around.

# Contributing to Brovan

Thanks for taking the time to help improve Brovan.

Brovan is a work-in-progress emulator project, and contributions of all sizes are welcome. You do not need to be an expert to contribute. Small fixes, documentation improvements, bug reports, and code changes are all useful.

## Before you start

Before contributing, please read the wiki pages on:

- emulator architecture
- emulator usage
- project setup
- debugging and troubleshooting

These pages explain how Brovan is structured and how to run it locally, which will help you understand the code! You can find them on the wiki here: https://github.com/AdvDebug/Brovan/wiki

A good first contribution is usually one of these:

- fixing a small bug
- improving a comment or piece of documentation
- cleaning up code that is confusing
- reproducing and reporting a bug clearly
- performance optimizations
- adding a syscall or improving existing ones
- just testing the emulator and finding general bugs

And keep your changes small. smaller changes in chunks and separate PRs are much better than a very big PR that is harder to review.

## How to contribute

1. Fork the repository.
2. Clone your fork locally.
3. Create a new branch for your change.
4. Make your change.
5. Test it as well as you can.
6. Open a pull request.

## Pull request guidelines

Please keep pull requests focused on one thing at a time.

Good pull requests:

- are small and easy to review
- explain what changed and why
- include steps to test the change
- mention any known limitations

If your change affects behavior, please describe how to reproduce the issue before the fix and how to verify the fix after it.

## Code style

Please try to match the style of the surrounding code.

A few simple rules help a lot:

- keep changes minimal and readable
- use clear names
- avoid adding extra complexity unless it solves a real problem
- follow the patterns already used in the file you are editing (for example some files have summaries, so add function summaries so other people that contributes understands your code, etc)

## Testing

Before opening a pull request, run the project and verify your change if possible.

If you cannot fully test something, that is okay. Just say what you tested and what still needs verification, and i will take care of the rest.

## Reporting bugs

A good bug report should include:

- what you were trying to do
- what happened
- what you expected to happen
- steps to reproduce
- logs, screenshots, or crash output if available

Clear bug reports make it much easier to fix problems quickly.

## Some stuff to work on

You can look at <a href="https://github.com/AdvDebug/Brovan/blob/main/IDEAS.md">IDEAS.md</a> as a start, containing some ideas that came on the top of my head. but improvements can be made anywhere, as the project still has a lot to be worked on.

## Need help?

If something is unclear, open an issue for the project. It is fine to ask questions before making a pull request. you can also contact me on discord if you want to ask privately.

## Thank you

Every contribution matters. Brovan gets better because people take the time to improve it.

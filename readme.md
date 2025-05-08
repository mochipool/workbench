# Problem Statement

Typical SPO maintenance operations can be a hassle especially when you're working across multiple machines, and application versions change. For anyone looking to just get up-and-running, there is currently no effective, reproducible solution.

Guild Operators provide a really convenient deploy script to get the executables you need, `guild-deploy.sh`, but this only works on some variants of Linux. If you're using Arch for instance, you're out of luck. Not only that, but it modifies your current machine's directory structure.

What happens when you want to use the [SPO Scripts from Martin Lang](https://github.com/gitmachtl/scripts)? Right - another thing to configure.

Or what about when you want to change from a mainnet environment to testnet? Gotta reconfigure or move some files around...bummer.

Sure, you can spend your time creating scripts upon scripts to automate this process, maybe even spin up a VM or container to isolate from your machine's filesystem, but then that's a lot of overhead to deal with.

But, we have a better way...

# Mochi's SPO Workbench
Introducing *Mochi's SPO Workbench* - a collection of common tools and binaries for the SPO who just wants to get up-and-running.

Using the amazing Nix language, your can configure your system in a robust, repeatable way, without having to worry about your user filesystem getting cluttered.

Want to change environments? Easy, just set it in the flake configuration; all dependencies will be accounted for.

Want to use a specific version of cardano-node? No problem, just set the appropriate git ref in the flake and all your configurations will be updated.

Try it out and see if you like it. PRs are always welcome!

# Quick Start

First, make sure Nix is installed on your system. The easiest way is to use the [Determinate Systems Nix Installer](https://docs.determinate.systems/).

```sh
curl -fsSL https://install.determinate.systems/nix | sh -s -- install --determinate
```

Clone the repo

```sh
git clone https://github.com/mochipool/workbench.git
cd workbench
```

Enter a dev shell

```sh
# Mainnet is the default
nix develop --accept-flake-config

# Or choose a specific network
nix develop --accept-flake-config .#preview
```

Great! Now you're off to the races 🎉

# Customization

## SPO Scripts
Although the envrionments are pre-configured with all you'd need to run the spo-scripts, sometimes it is desirable to change parameter. The files provided by Nix are not meant to be changed, but you can still include a `common.inc` file in the working directory, which overrides all parameters in `.common.inc`.


# Testing
To test validation functions for example, run the following nix repl commands:
```sh
# Start repl
nix repl

# Load files and libs
:lf .
lib = (import <nixpkgs> {}).lib
validators = import ./validators.nix { inherit lib; }

# Then test functions like
validators.network.normalize "Preview"
```

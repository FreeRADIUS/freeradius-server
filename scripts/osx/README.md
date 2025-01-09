# Building on OSX
FreeRADIUS can be installed on OSX platforms, however some environment setup is required. Additional dev tools are also configured before the server installation.

## Environment Setup

Install the (Homebrew)[https://brew.sh] package manager to streamline the installation process on OSX platforms.

Run the `install_deps.sh` script to install the build dependencies. It's recommended to create a copy of this file and edit locally. You can remove apps, libs, or utilites that you don't need such as postgresql. Ensure that you use the updated file when running the script.

Install Xcode from the (app store)[https://www.apple.com/ca/app-store/]. This tool is used to help develop, test, and manage your applications.

Install the xcode command-line tools.

```
xcode-select --install
```

Update the `~/.zshrc` file.

```
cat scripts/osx/bash_profile >> ~/.zshrc
```
Note: if using a different shell, ensure you copy the environment paramenters to your current shell.

### Getting the Source

Open a new shell and navigate to the directory where you want to install the FreeRADIUS server.

Download the lastest version from a git repository:

```
git clone https://github.com/FreeRADIUS/freeradius-server.git
```

#### Installation/Configuration

To begin the install process issue the following commands:

```
cd freeradius-server
./configure
make
```

##### Running FreeRADIUS in the background all of the time.

The information below is for future reference.

```
cp ./org.freeradius.radius.plist /Library/LaunchDaemons
launchctl load -w Library/LaunchDaemons/org.freeradius.radiusd.plist
```

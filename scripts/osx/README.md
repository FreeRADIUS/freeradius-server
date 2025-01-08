# OSX

Install (Homebrew)[https://brew.sh].

Run the `install_deps.sh` script to install the build dependencies.
You may want to copy it to a local file and remove things you don't
care about such as postgresql, etc.

Install Xcode from the app store.

Install the xcode command-line tools.

```
xcode-select --install
```

Update the `~/.zshrc`

```
cat scripts/osx/bash_profile >> ~/.zshrc
```

Open a new shell.

```
git clone https://github.com/FreeRADIUS/freeradius-server.git
cd freeradius-server
./configure
make
```


## Running FreeRADIUS in the background all of the time.

You don't need this.  It's here for future reference.

```
cp ./org.freeradius.radius.plist /Library/LaunchDaemons
launchctl load -w Library/LaunchDaemons/org.freeradius.radiusd.plist
```
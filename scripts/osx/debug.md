# Debugging on OSX

The program has to be signed:

````
codesign -s - -v -f --entitlements ./scripts/osx/debug.plist ./build/bin/local/radiusd
```


Start it up in Xcode with a full path to the executable:
`/PATH/build/bin/local/radiusd`.  Usually done via `open
./build/bin/local` and then dragging the `radius` program to the file selector in Xcode.

Set command-line arguments:

```
-fxx -l stdout -m -d /PATH/raddb -D /PATH/share
```

And environment variables.

```
DYLD_FALLBACK_LIBRARY_PATH=/Users/alandekok/git/v3.2.x/build/lib/.libs>
FR_LIBRARY_PATH=/Users/alandekok/git/v3.2.x/build/lib/local/.libs
```

Pass signals in `lldb` directly to the program:

```
(lldb) pro hand -p true -s false SIGHUP
```

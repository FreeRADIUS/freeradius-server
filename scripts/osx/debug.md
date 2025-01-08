# Debugging on OSX

We assume that all of the code is in a particular path:

```
FR_PATH=$(HOME)/
```

The program has to be signed:

````
cd $(FR_PATH)
codesign -s - -v -f --entitlements ./scripts/osx/debug.plist ./build/bin/local/radiusd
```


Start it up in Xcode with a full path to the executable:
`$(FR_PATH)/build/bin/local/radiusd`.  Usually done via `open
./build/bin/local` and then dragging the `radius` program to the file selector in Xcode.

Set command-line arguments:

```
-fxx -l stdout -m -d $(FR_PATH)/raddb -D $(FR_PATH)/share
```

And environment variables.

```
DYLD_FALLBACK_LIBRARY_PATH=$(FR_PATH)/build/lib/.libs>
FR_LIBRARY_PATH=$(FR_PATH)/build/lib/local/.libs
```

Pass signals in `lldb` directly to the program:

```
(lldb) pro hand -p true -s false SIGHUP
```

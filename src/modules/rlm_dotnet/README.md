# rlm_dotnet

## What I did for configuration

With Homebrew on OS X:

`./configure --with-openssl-lib-dir=/usr/local/opt/openssl@1.1/lib --with-openssl-include-dir=/usr/local/opt/openssl@1.1/include`

<https://github.com/dotnet/samples/tree/master/core/hosting/HostWithCoreClrHost>
<https://github.com/dotnet/docs/blob/master/docs/core/tutorials/netcore-hosting.md>

`sudo make install` put everything in /usr/local as expected

`sudo ln -s ../mods-available/dotnet dotnet` from `/usr/local/etc/raddb/mods-enabled`
`sudo /usr/local/sbin/radiusd -X` to run

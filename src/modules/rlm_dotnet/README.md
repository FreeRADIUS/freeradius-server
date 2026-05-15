# rlm_dotnet



`rlm_dotnet` hosts a .NET 8+ assembly inside FreeRADIUS **v3.0.x** using `hostfxr` and `nethost`. Managed code receives a **versioned binary snapshot** (`RDb1` v1) of RADIUS pair lists (see `RadiusRequestBlob` in the interop assembly) and may return reply attributes as a UTF-8 pair-list string or a binary **`RDr1`** reply blob. Module boot uses a small **JSON** object passed to `Instantiate`.



## Request blob v1 (C / managed contract)



- **Magic** `RDb1`, **format version** `1` (big-endian `uint16` after magic).

- **Header** 12 bytes: magic (4), version (2), flags (2), **payload length** (4, big-endian; must equal file size minus 12).

- **Payload**: UTF-8 **section** (`uint16` length + bytes), **`num_lists`** `uint16` BE (`4` without `WITH_PROXY`, `6` with proxy lists).

- **Each list**: `uint32` BE pair count, then that many **VP records**: attribute name (`uint16` UTF-8 length + bytes), `int8` tag, `uint8` op (`FR_TOKEN`), `uint8` value flags (`0x01` = XLAT template), `uint8` reserved, `uint16` BE `PW_TYPE`, `uint32` BE value length, raw value bytes.

- **List order**: packet, reply, config, session_state [, proxy_request, proxy_reply if `WITH_PROXY`].



## Reply blob v1 (`RDr1`)



Symmetric VP record layout (no section / num_lists wrapper):



- **Magic** `RDr1`, **version** `1`, **flags** `uint16` BE (`0x02` = merge into `request->reply`, default).

- **Payload**: `uint32` BE pair count + VP records (same as request VP records).



Use `RadiusReply.FromBlob(RadiusReplyBlob.Encode(vps))` from managed code, or return a pair-list string (default).



## Authorize ABI



Hostfxr exports: **`Instantiate`**, **`Detach`**, and (when `policy_instance_mode = per_thread`) **`EnsureThreadPolicy`**.



Boot JSON includes `publish_authorize_fn`, `authorize_fn_out`, `policy_instance_mode`, `async_timeout_ms`, and `extra`.



Native **`AuthorizeBlob`** signature:



`(handle, requestBlob, requestLen, replyBuf, replyBufLen, outWritten, outReplyFormat, errorBuf, errorBufLen, outErrorWritten)`



- `outReplyFormat`: `0` = UTF-8 pair-list in `replyBuf`, `1` = `RDr1` binary blob.

- On `RLM_MODULE_FAIL`, `errorBuf` may contain JSON: `{"category","message","stack"}`.



**Upgrade:** Deploy **`rlm_dotnet`** and the published **interop DLL** from the same tree/revision together.



## Threading and policy instances



Registered as **`RLM_TYPE_THREAD_SAFE | RLM_TYPE_HUP_SAFE`**.



| `policy_instance_mode` | Behavior |

|------------------------|----------|

| `shared` (default) | One policy instance for all worker threads; must be thread-safe if mutable. |

| `per_thread` | Factory at module level; each worker lazily gets its own policy via `EnsureThreadPolicy`. Use for per-thread `HttpClient`, caches, etc. Thread policies are detached when the worker thread exits. |



Alternatively, set the module to `RLM_TYPE_THREAD_UNSAFE` in `rlm_dotnet.c` for global serialization.



## Async policies



Implement **`IAsyncRadiusPolicy`** for outbound I/O (`HttpClient`, databases). The native entrypoint still **blocks the RADIUS worker** until completion (sync bridge). Optional **`async_timeout_ms`** in config aborts hung async calls.



## HUP (reload), CLR lifetime, and assemblies

The module is **`RLM_TYPE_HUP_SAFE`**: FreeRADIUS may instantiate a new module instance on `SIGHUP` and detach the old one after configuration reload.

- **Configuration reload (HUP):** `radiusd.conf` module options, virtual-server sections, and `extra_config` can change without restarting the process.
- **No managed hot reload:** Updated `FreeRadius.Dotnet.Interop.dll`, policy assemblies, or any change that requires reloading IL **still needs a full `radiusd` process restart**. HUP does not unload the CLR or reload assemblies from disk; the runtime and loaded assemblies stay in the process until exit.
- The CLR is **not** shut down in `detach` (unreliable from a native host).
- Per-instance `GCHandle` state is freed when the **old** instance is detached after reload; static / process-wide managed caches survive until process exit.



## Module options



| Option | Default | Description |

|--------|---------|-------------|

| `reply_buffer_size` | `65536` | Reply buffer (pair-list or `RDr1`) |

| `error_buffer_size` | `8192` | Error JSON buffer |

| `policy_instance_mode` | `shared` | `shared` or `per_thread` |

| `async_timeout_ms` | `0` | Async policy timeout (`0` = none) |

| `stats` | `yes` | Record calls, failures, latency |

| `stats_log_interval` | `0` | Seconds between periodic `L_INFO` stats lines (`0` = detach only) |



## Metrics

When `stats = yes`, the module accumulates per-instance **calls**, **failures**, **total latency**, and **last request latency** (microseconds). Latency uses **`CLOCK_MONOTONIC`** when available (not affected by wall-clock changes); otherwise `gettimeofday()`.

- **Detach:** one summary line with totals and average latency.
- **`stats_log_interval` > 0:** additional periodic summaries (approximately every N seconds) including **calls/sec** since the previous interval log.

Example interval line:

```text
rlm_dotnet (dotnet) stats [interval]: calls=12040 failures=3 avg_ms=1.234 last_ms=0.891 calls_per_sec=4013.33
```

## Reply blob decoding

`RDr1` VP records include a wire `pw_type`, but native decode uses **`dict_attrbyname()`** for the canonical attribute type; `fr_pair_value_memcpy()` stores octets according to the dictionary, which matches typical FreeRADIUS usage.



## Boot JSON



String paths are **JSON-escaped** in C. **`extra_config`** must be a JSON **object** (e.g. `{"note":"..."}`).



## Build (Linux)



1. Install .NET SDK / `nethost` (see existing `configure` checks).

2. `./configure && make` in the FreeRADIUS tree.

3. Publish the interop assembly:



   ```text

   dotnet publish -c Release dotnet/FreeRadius.Dotnet.Interop/FreeRadius.Dotnet.Interop.csproj \

     -o dotnet/publish/Release --no-self-contained

   ```



## `radiusd.conf` example



```text

modules {

  dotnet {

    assembly_path = /path/to/FreeRadius.Dotnet.Interop.dll

    native_exports_type = "FreeRadius.Interop.NativeExports, FreeRadius.Dotnet.Interop"

    policy_type = "FreeRadius.Interop.ExamplePolicy, FreeRadius.Dotnet.Interop"

    policy_instance_mode = shared

    reply_buffer_size = 65536

    error_buffer_size = 8192

    async_timeout_ms = 0

    stats = yes

    extra_config = "{\"note\":\"optional\"}"

  }

}



authorize {

  dotnet

}

```



## Reply list syntax (string mode)



```text

Reply-Message := "Welcome", Filter-Id := "premium"

```



Parsed with `fr_pair_list_afrom_str` into `request->reply`.



## Regenerating `configure`



See `configure.ac` and `make reconfig` in this directory.



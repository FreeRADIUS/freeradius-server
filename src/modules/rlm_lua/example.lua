local function tprint (tbl, indent)
  if not indent then indent = 0 end

  for k, v in tbl.pairs() do
    local formatting = string.rep("  ", indent) .. k .. ": "
    if type(v) == "table" then
      print(formatting)
      tprint(v, indent+1)
    else
      print(formatting .. '"' .. v .. '" (' .. type(v) .. ')')
    end
  end
end

function recv_accounting_request()
  print("example.lua/recv_accounting_request()")
  return fr.rcode.ok
end

function accounting()
  print("example.lua/accounting()")
  return fr.rcode.ok
end

function send()
  print("example.lua/send()")
  return fr.rcode.ok
end

function instantiate()
  print("example.lua/instantiate()")
  return fr.rcode.ok
end

function detach()
  print("example.lua/detach()")
  return fr.rcode.ok
end

function recv_access_request()
  print("example.lua/recv_access_request()")
  return fr.rcode.ok
end

function authorize()
  -------------------------
  -- example invocations --
  -------------------------

  --print(fr.request['User-Name'][1])
  --tprint(fr.request['User-Name'])
  --fr.control['Password']['Cleartext'][1] = 'topsecret'
  --fr.reply['Framed-IP-Address'][1] = '192.168.1.20'

  print("example.lua/authorize()")
  print("Request list contents:")
  tprint(fr.request, 2)

  return fr.rcode.ok
end

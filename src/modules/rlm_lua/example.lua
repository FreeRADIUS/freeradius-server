function tprint (tbl, indent)
  if not indent then indent = 0 end

  for k, v in tbl.pairs() do
    formatting = string.rep("  ", indent) .. k .. ": "
    if type(v) == "table" then
      print(formatting)
      tprint(v, indent+1)
    else
      print(formatting .. '"' .. v .. '" (' .. type(v) .. ')')
    end
  end
end

function preacct()
  print("example.lua/preacct()")
  return fr.ok
end

function accounting()
  print("example.lua/accounting()")
  return fr.ok
end

function pre_proxy()
  print("example.lua/pre_proxy()")
  return fr.ok
end

function post_proxy()
  print("example.lua/post_proxy()")
  return fr.ok
end

function post_auth()
  print("example.lua/post_auth()")
  return fr.ok
end

function recv_coa()
  print("example.lua/recv_coa()")
  return fr.ok
end

function send_coa()
  print("example.lua/send_coa()")
  return fr.ok
end

function detach()
  print("example.lua/detach()")
  return fr.ok
end

function xlat()
  print("example.lua/xlat()")
  return fr.ok
end

function authenticate()
  print("example.lua/authenticate()")
  return fr.ok
end

function authorize()
  -------------------------
  -- example invocations --
  -------------------------

  --tprint(get_attribute("user-name"))
  --tprint(get_attribute("user-password"))
  --tprint(get_attribute("tunnel-type", "2"))
  --print(request['user-name'][0])
  --print(request['user-name'].next_iter())
  --print(request['user-name'].next_iter())
  --tprint(request['user-name'])
  --tprint(request['user-name'])

  print("example.lua/authorize()")
  print("Request list contents:")
  tprint(request, 2)

  return fr.ok
end

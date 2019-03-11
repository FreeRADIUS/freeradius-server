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
end

function accounting()
  print("example.lua/accounting()")
end

function pre_proxy()
  print("example.lua/pre_proxy()")
end

function post_proxy()
  print("example.lua/post_proxy()")
end

function post_auth()
  print("example.lua/post_auth()")
end

function recv_coa()
  print("example.lua/recv_coa()")
end

function send_coa()
  print("example.lua/send_coa()")
end

function detach()
  print("example.lua/detach()")
end

function xlat()
  print("example.lua/xlat()")
end

function authenticate()
  print("example.lua/authenticate()")
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
end

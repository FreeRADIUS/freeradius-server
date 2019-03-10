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
  print("example.lua/preacct() Dummy")
end

function accounting()
  print("example.lua/accounting() Dummy")
end

function pre_proxy()
  print("example.lua/pre_proxy() Dummy")
end

function post_proxy()
  print("example.lua/post_proxy() Dummy")
end

function post_auth()
  print("example.lua/post_auth() Dummy")
end

function recv_coa()
  print("example.lua/recv_coa() Dummy")
end

function send_coa()
  print("example.lua/send_coa() Dummy")
end

function detach()
  print("example.lua/detach() Dummy")
end

function xlat()
  print("example.lua/xlat() Dummy")
end

function authenticate()
  print("example.lua/authenticate() Dummy")
end

function authorize()
  print("example.lua/authorize(): <list_request>")
  tprint(request, 2)
  print("example.lua/authorize: </list_request>")
end

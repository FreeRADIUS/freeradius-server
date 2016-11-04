function tprint (tbl, indent)
  if not indent then indent = 0 end
  for k, v in pairs(tbl) do
    formatting = string.rep("  ", indent) .. k .. ": "
    if type(v) == "table" then
      print(formatting)
      tprint(v, indent+1)
    else
      print(formatting .. v)
    end
  end
end


function authenticate()

end

function authorize()


	request['user-name'][2] = nil

        for i in request['user-name'].pairs() do
                print(i)
        end


        for k,v in request.pairs_list() do
                print(k,v)
        end


	--tprint(get_attribute("user-name"))
	--tprint(get_attribute("user-password"))
	--tprint(get_attribute("tunnel-type", "2"))
	--print(request['user-name'][0])
	--print(request['user-name'].next_iter())
	--print(request['user-name'].next_iter())
	--tprint(request['user-name'])
	--tprint(request['user-name'])
end

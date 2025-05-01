-- Tests which access / manipulate attributes

-- Check access to simple pairs in the root of the list
function fetch_root()
    if fr.request['User-Name'][1] ~= 'bob' then return fr.rcode.fail end
    if fr.request['User-Name'][2] then return fr.rcode.fail end
    return fr.rcode.ok
end

-- Check access to nested pairs
function fetch_nested()
    if fr.request['Vendor-Specific']['Cisco']['AVPair'][1] ~= "cisco=madness" then return fr.rcode.fail end
    if fr.request['Vendor-Specific']['Cisco']['AVPair'][2] ~= "is=crazy" then return fr.rcode.fail end
    if fr.request['Vendor-Specific']['3GPP2']['DNS-Server']['Primary-IP-Address'][1] ~= "8.8.8.8" then return fr.rcode.fail end
    if fr.request['Net']['Src']['IP'][1] ~= '127.0.0.1' then return fr.rcode.fail end
    return fr.rcode.ok
end

-- Check setting a simple pair
function set_simple()
    fr.request['NAS-Identifier'][1] = 'Test NAS'
    return fr.rcode.ok
end

-- Check overwriting an existing simple attribute
function overwrite_simple()
    fr.request['User-Name'][1] = 'john'
    return fr.rcode.ok
end

-- Check setting nested pairs
function set_nested()
    fr.control['Vendor-Specific']['Cisco']['AVPair'][1] = 'very=special'
    fr.request['Vendor-Specific']['3GPP2']['DNS-Server']['Secondary-IP-Address'][1] = '1.1.1.1'
    fr.request['Vendor-Specific']['3GPP2']['DNS-Server'][2]['Primary-IP-Address'][1] = '10.9.8.7'
    fr.request['Vendor-Specific']['Cisco']['AVPair'][3] = 'top=secret'
    return fr.rcode.updated
end

-- Check updating an existing nested pair
function overwrite_nested()
    fr.request['Vendor-Specific']['Cisco']['AVPair'][2] = 'silly=idea'
    fr.request['Vendor-Specific']['3GPP2']['DNS-Server'][2]['Primary-IP-Address'][1] = '1.2.3.4'
    return fr.rcode.updated
end

-- Check the type of values returned from pairs()
function list_pairs()
    for k, v in fr.request.pairs() do
        if ((k == 'Vendor-Specific') or (k == 'Net')) then
            if (type(v) ~= 'table') then return fr.rcode.fail end
        else
            if ((type(v) ~= 'string') and (type(v) ~= 'number')) then return fr.rcode.fail end
        end
        print(k, type(v))
    end
    return fr.rcode.noop
end

-- Check retrieving all the instances of an attribute using pairs()
function attribute_pairs()
    local i = 0
    for v in fr.request['Vendor-Specific']['Cisco']['AVPair'].pairs() do
        i = i + 1
        if (i == 1) and (v ~= 'cisco=madness') then return fr.rcode.fail end
        if (i == 2) and (v ~= 'silly=idea') then return fr.rcode.fail end
        if (i == 3) and (v ~= 'top=secret') then return fr.rcode.fail end
    end
    if i ~= 3 then return fr.rcode.fail end
    return fr.rcode.ok
end

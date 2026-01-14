-- Tests which access / manipulate attributes

-- Check deleting a simple attribute from the list root.
function del_from_root()
    fr.request['User-Name'][1] = nil
    return fr.rcode.updated
end

-- Check deleting a nested attribute
function del_nested()
    if fr.request['Vendor-Specific']['Cisco']['AVPair'][2] ~= "is=crazy" then return fr.rcode.fail end
    fr.request["Vendor-Specific"]["Cisco"]["AVPair"][1] = nil
    if fr.request["Vendor-Specific"]["Cisco"]["AVPair"][2] then return fr.rcode.fail end
    return fr.rcode.updated
end

-- Check deleting a pair that doesn't exist
function del_missing()
    fr.request['NAS-Identifier'][1] = nil
    return fr.rcode.noop
end

-- Check attempting to delete the pair table fails.
function del_invalid()
    fr.request['User-Password'] = nil
    return fr.rcode.ok
end

-- Check attempting to delete a nested pair table fails.
function del_invalid_nested()
    fr.request['Vendor-Specific']['Cisco'] = nil
    return fr.rcode.ok
end

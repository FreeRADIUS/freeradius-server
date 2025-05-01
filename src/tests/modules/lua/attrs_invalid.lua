-- Tests which access / manipulate attributes in an invalid way.
-- These will all result in a module failure as the C function will return the
-- appropriate value to indicate failure.

-- Check setting a simple pair instance 2 when none exist
function set_simple()
    fr.request['NAS-Identifier'][2] = 'Test NAS'
    return fr.rcode.ok
end

-- Check setting a pair rather than an instance of a pair
function set_pair()
    fr.request['Filter-Id'] = 'john'
    return fr.rcode.ok
end

-- Check setting nested pairs - invalid index and direct pair setting
function set_nested_1()
    fr.control['Vendor-Specific']['Cisco']['AVPair'][5] = 'very=special'
    return fr.rcode.updated
end
function set_nested_2()
    fr.request['Vendor-Specific']['3GPP2']['DNS-Server'][3]['Primary-IP-Address'][1] = '10.9.8.7'
    return fr.rcode.updated
end
function set_nested_3()
    fr.control['Vendor-Specific']['Cisco']['AVPair'] = 'very=special'
    return fr.rcode.updated
end
function set_nested_4()
    fr.request['Vendor-Specific']['3GPP2']['DNS-Server'][1] = '10.9.8.7'
    return fr.rcode.updated
end


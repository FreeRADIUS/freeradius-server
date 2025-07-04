module FreeRADIUS

  # Check access to simple pairs in the root of the list
  def self.fetch_root(p)
    if p.request.user_name.get != 'bob' then return RLM_MODULE_FAIL end
    if p.request.user_name.get(1) != nil then
      log(L_WARN, p.request.user_name.get(2))
      return RLM_MODULE_FAIL
    end
    return RLM_MODULE_OK
  end

  # Check access to nested pairs
  def self.fetch_nested(p)
    if p.request.vendor_specific.cisco.avpair.get != 'cisco=madness' then return RLM_MODULE_FAIL end
    if p.request.vendor_specific.cisco.avpair.get(1) != 'is=crazy' then return RLM_MODULE_FAIL end
    if p.request.vendor_specific('3GPP2').dns_server.primary_ip_address.get != '8.8.8.8' then return RLM_MODULE_FAIL end
    if p.request.net.src.ip.get != '127.0.0.1' then return RLM_MODULE_FAIL end
    return RLM_MODULE_OK
  end

  # Check setting a simple pair
  def self.set_simple(p)
    p.request.nas_identifier.set('Test NAS')
    return RLM_MODULE_OK
  end

  # Check overwriting an existing simple attribute
  def self.overwrite_simple(p)
    p.request.user_name.set('john')
    return RLM_MODULE_OK
  end

  # Check setting nested pairs
  def self.set_nested(p)
    p.control.vendor_specific.cisco.avpair.set('very=special')
    p.request.vendor_specific('3GPP2').dns_server.secondary_ip_address.set('1.1.1.1')
    p.request.vendor_specific('3GPP2').dns_server(1).primary_ip_address.set('10.9.8.7')
    p.request.vendor_specific.cisco.avpair.set('top=secret', 2)
    return RLM_MODULE_UPDATED
  end

  # Check updating an existing nested pair
  def self.overwrite_nested(p)
    p.request.vendor_specific.cisco.avpair.set('silly=idea', 1)
    p.request.vendor_specific('3GPP2').dns_server(1).primary_ip_address.set('1.2.3.4')
    return RLM_MODULE_UPDATED
  end

  # Check the keys method works
  def self.list_pairs(p)
    p.request.keys.each do |attr|
      log(L_INFO, attr)
    end
    return RLM_MODULE_NOOP
  end

  # Check deleting a simple attribute from the list root.
  def self.del_from_root(p)
    p.request.user_name.del
    return RLM_MODULE_UPDATED
  end

  # Check deleting a nested attribute
  def self.del_nested(p)
    if p.request.vendor_specific.cisco.avpair.get(1) != 'is=crazy' then return RLM_MODULE_FAIL end
    p.request.vendor_specific.cisco.avpair.del
    if p.request.vendor_specific.cisco.avpair.get(1) != nil then return RLM_MODULE_FAIL end
    return RLM_MODULE_UPDATED
  end

  # Check deleting a pair that doesn't exist
  def self.del_missing(p)
    p.request.nas_identifier.del
    return RLM_MODULE_NOOP
  end

end

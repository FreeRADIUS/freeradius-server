module FreeRADIUS

  # Check setting a simple pair instance 1 when none exist
  def self.set_simple(p)
    p.request.nas_identifier.set('Test NAS', 1)
    return RLM_MODULE_OK
  end

  # Check setting a string against a numeric
  def self.set_type(p)
    p.request.nas_port.set('john')
    return RLM_MODULE_OK
  end

  # Check setting nested pairs - invalid instance
  def self.set_nested_1(p)
    fr.control.vendor_specific.cisco.avpair.set('very=special', 4)
    return RLM_MODULE_UPDATED
  end
  def self.set_nested_2(p)
    fr.request.vendor_specific('3GPP2').dns_server(3).primary_ip_address.set('10.9.8.7')
    return RLM_MODULE_UPDATED
  end

end

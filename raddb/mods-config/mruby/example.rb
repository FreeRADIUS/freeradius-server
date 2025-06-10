#This is example radius.rb script

# frozen_string_literal: true

module FreeRADIUS
    def self.instantiate
        log(L_DBG, "Running ruby instantiate")
        return RLM_MODULE_OK
    end
    def self.authenticate(p)
        log(L_DBG, "Running ruby authenticate")
        return RLM_MODULE_NOOP
    end
    def self.recv_access_request(p)
        log(L_DBG, "Running ruby recv_access_request")
        log(L_WARN, "Authorize: #{p.request.user_name.get.inspect}")
	p.reply.framed_mtu.set(1500)
	p.control.password.cleartext.set('hello')
        return RLM_MODULE_UPDATED
    end
    def self.send_access_accept(p)
        log(L_DBG, "Running ruby send_access_accept")
        return RLM_MODULE_NOOP
    end
    def self.recv_accounting_request(p)
        log(L_DBG, "Running ruby accounting")
        return RLM_MODULE_NOOP
    end
end

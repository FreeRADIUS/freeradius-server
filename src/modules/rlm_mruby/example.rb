#This is example radius.rb script
module Radiusd
    def self.instantiate()
        radlog(L_DBG, "[mruby]Running ruby instantiate")
        return RLM_MODULE_OK
    end
    def self.authenticate(request)
        radlog(L_DBG, "[mruby]Running ruby authenticate")
        return RLM_MODULE_NOOP
    end
    def self.authorize(request)
        radlog(L_ERR, "[mruby]Running ruby authorize")
        radlog(L_WARN, "Authorize: #{request.inspect}(#{request.class})")
        radlog(L_WARN, "Authorize: #{request.request.inspect}(#{request.request.class})")
    
        reply = [["Framed-MTU", 1500]]
        control = [["Password.Cleartext", "hello"], ["Tmp-String-0", "!*", "ANY"]]
        return [RLM_MODULE_UPDATED, reply, control]
    end
    def self.post_auth(request)
        radlog(L_DBG, "[mruby]Running ruby post_auth")
        return RLM_MODULE_NOOP
    end
    def self.accounting(request)
        radlog(L_DBG, "[mruby]Running ruby accounting")
        return RLM_MODULE_NOOP
    end
end

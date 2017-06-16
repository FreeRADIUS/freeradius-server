TARGETNAME	:= 

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c

SRC_CFLAGS	:= -Wno-unknown-warning-option  -g -Os -pipe -DHAVE_GCC_SYNC_BUILTINS  -isystem /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/System/Library/Frameworks/Ruby.framework/Versions/2.0/usr/include/ruby-2.0.0 -isystem /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/System/Library/Frameworks/Ruby.framework/Versions/2.0/usr/include/ruby-2.0.0/universal-darwin15
TGT_LDLIBS	:=  -L/System/Library/Frameworks/Ruby.framework/Versions/2.0/usr/lib -lruby.2.0.0 

ifneq "$(TARGETNAME)" ""
install: $(R)$(modconfdir)/ruby/example.rb

$(R)$(modconfdir)/ruby: | $(R)$(modconfdir)
	@echo INSTALL $(patsubst $(R)$(raddbdir)%,raddb%,$@)
	@$(INSTALL) -d -m 750 $@

$(R)$(modconfdir)/ruby/example.rb: src/modules/rlm_ruby/example.rb | $(R)$(modconfdir)/ruby
	@$(ECHO) INSTALL $(notdir $<)
	@$(INSTALL) -m 755 $< $(R)$(modconfdir)/ruby
endif

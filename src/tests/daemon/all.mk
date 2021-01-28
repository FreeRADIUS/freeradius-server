#
#  Don't bother running the shell commands every time.
#  If the file exists,
#
ifeq "$(wildcard $(BUILD_DIR)/tests/tmux.key)" ""

MD5SUM	:= $(shell which md5sum 2>/dev/null)
TMUX	:= $(shell which tmux 2>/dev/null)

ifneq "$(MD5SUM)" ""
ifneq "$(TMUX)" ""

#
#  Create a unique TMUX key for this user, directory, and machine
#
TMUX_KEY  := $(shell { (id; pwd; hostid || ifconfig -a) 2> /dev/null; } | md5sum | awk '{print $$1}')

endif
endif

else
#
#  The tmux.key file exists.  Use the contents as the key
#
TMUX_KEY  := $(shell cat $(wildcard $(BUILD_DIR)/tests/tmux.key))
endif

#
#  If we have a key, do the rest of the tests.
#
ifneq "$(TMUX_KEY)" ""

#
#  Make a random port which depends on the last 3 hex digits of the
#  TMUX key.  This is so that the various instances of radiusd don't
#  stomp on each others ports.
#
TMUX_PORT := $(shell expr 32768 + $$(printf "%d\n" 0x$$(echo $(TMUX_KEY) | grep -o '...$$' )))

#
#  Save the key so that the user knows what it is
#
.PHONY: $(BUILD_DIR)/tests/tmux.key
$(BUILD_DIR)/tests/tmux.key:
	${Q}echo $(TMUX_KEY) > $@

#
#  Stupid 'make' doesn' know how to create directories.
#
.PHONY: $(BUILD_DIR)/tests/daemon/
$(BUILD_DIR)/tests/daemon/:
	${Q}mkdir -p $@

#
#  A place-holder to ensure we're running the correct version of radiusd.
#
#  If the daemon changes, we kill any running tests, and start over.
#  If the tmux session isn't running, that's OK, too.
#
$(BUILD_DIR)/tests/daemon/radiusd.version: $(TEST_BIN_DIR)/radiusd
	${Q}tmux -L $(TMUX_KEY) send-key C-c 2>/dev/null || true
	${Q}tmux -L $(TMUX_KEY) kill-server 2>/dev/null || true
	${Q}rm -f $(BUILD_DIR)/tests/daemon/radiusd.log
	${Q}touch $@

#
#  The output log file is created by running the server.
#
$(BUILD_DIR)/tests/daemon/radiusd.log: $(BUILD_DIR)/tests/daemon/radiusd.version
	${Q}rm -f $@
	${Q}tmux -L $(TMUX_KEY) new-session -d './$(TEST_BIN)/radiusd -i 127.0.0.1 -p $(TMUX_PORT) -fxx -d ./raddb -D share/dictionary -l $@'

radiusd.start: $(BUILD_DIR)/tests/daemon/radiusd.log

#
#  Killing the TMUX session doesn't kill the child process <sigh>
#  So we kill the radiusd daemon first, then kill the session.
#
#  We don't care if the session is running or not, either.
#
#  We delete the log file, because it's a clean exit.
#
.PHONY: radiusd.stop
radiusd.stop:
	${Q}tmux -L $(TMUX_KEY) send-key C-c 2>/dev/null || true
	${Q}tmux -L $(TMUX_KEY) kill-server 2>/dev/null || true
	${Q}rm -f $(BUILD_DIR)/tests/daemon/radiusd.log

endif

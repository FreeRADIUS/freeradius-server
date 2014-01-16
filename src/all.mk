# add this dependency BEFORE including the other submakefiles.
all:

#
#  This nonsense is here because pattern rules don't work if you have
#  multiple of them.  If you try to run the shell script by assigning
#  it to a variable, GNU Make notices that the variable isn't used...
#  and doesn't run the shell script.  This crap below seems to bypass
#  Make's optimization.
#
ifeq "$(shell [ -e src/freeradius-devel ] || ln -s include src/freeradius-devel)" ""
# do nothing
endif

SUBMAKEFILES := include/all.mk lib/all.mk tests/all.mk modules/all.mk main/all.mk

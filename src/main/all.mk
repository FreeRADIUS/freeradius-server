SUBMAKEFILES := \
    radclient.mk \
    radict.mk \
    radiusd.mk \
    radsniff.mk \
    radmin.mk \
    radwho.mk \
    radsnmp.mk \
    radlast.mk \
    radtest.mk \
    radzap.mk \
    unit_test_attribute.mk \
    unit_test_map.mk \
    unit_test_module.mk \
    checkrad.mk \
    libfreeradius-server.mk \
    $(wildcard ${top_builddir}/src/main/*_ext/all.mk)

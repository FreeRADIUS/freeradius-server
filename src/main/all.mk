SUBMAKEFILES := \
    radclient.mk \
    radiusd.mk \
    radsniff.mk \
    radmin.mk \
    radattr.mk \
    radwho.mk \
    radsnmp.mk \
    radlast.mk \
    radtest.mk \
    radzap.mk \
    checkrad.mk \
    libfreeradius-server.mk \
    unittest.mk \
    $(wildcard ${top_builddir}/src/main/*_ext/all.mk)

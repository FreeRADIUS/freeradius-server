#!/bin/bash

#
#  This program is is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or (at
#  your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
#

#
#  Extremely basic script for building eapol_test from hostapd's master branch
#
#  On success will write progress to stderr, and a path to the eapol_test
#  binary to stdout, exiting with 0.
#
#  On error will exit with 1.
#
#  Note: We don't always build eapol_test.  If a copy is already present on the
#  system we use that in preference.  To always build eapol_test, set
#  FORCE_BUILD=1 in the environment.
#

TMP_BUILD_DIR="${BUILD_DIR}"
: ${TMP_BUILD_DIR:="$(mktemp -d -t eapol_test.XXXXX)"}
: ${HOSTAPD_DIR:="${TMP_BUILD_DIR}/hostapd"}
: ${WPA_SUPPLICANT_DIR:="${HOSTAPD_DIR}/wpa_supplicant"}

: ${BUILD_CONF_DIR:="$(dirname $0)/eapol_test"}
: ${EAPOL_TEST_PATH:="${BUILD_CONF_DIR}/eapol_test"}

if [ -z "${FORCE_BUILD}" ]; then
    if [ -e "${EAPOL_TEST_PATH}" ]; then
        echo "${EAPOL_TEST_PATH}"
        exit 0
    fi

    WHICH_EAPOL_TEST="$(which eapol_test)"
    if [ ! -z "${WHICH_EAPOL_TEST}" ]; then
        echo "${WHICH_EAPOL_TEST}"
        exit 0
    fi
fi

case "$OSTYPE" in
linux-gnu)
    BUILD_CONF_FILE="${BUILD_CONF_DIR}/config_linux"
    ;;

darwin*)
    BUILD_CONF_FILE="${BUILD_CONF_DIR}/config_osx"
    ;;

freebsd*)
    BUILD_CONF_FILE="${BUILD_CONF_DIR}/config_freebsd"
    ;;

*)
    echo "Don't have specific eapol_test build config for OS $OSTYPE.  Using linux build config"
    BUILD_CONF_FILE="${BUILD_CONF_DIR}/linux"
    ;;
esac

if [ ! -e "${BUILD_CONF_FILE}" ]; then
    echo "Missing build config file \"${BUILD_CONF_FILE}\" for OS $OSTYPE, please contribute one" 1>&2
    exit 1
fi

# Shallow clone so we don't use all Jouni's bandwidth

if ! [ -e "${HOSTAPD_DIR}/.git" ] && ! git clone --depth 1 http://w1.fi/hostap.git 1>&2 "${TMP_BUILD_DIR}/hostapd"; then
    echo "Failed cloning hostapd" 1>&2
    if [ -z "${BUILD_DIR}" ]; then rm -rf "$TMP_BUILD_DIR"; fi
    exit 1
fi

cp "$BUILD_CONF_FILE" "$WPA_SUPPLICANT_DIR/.config"

if ! make -C "${WPA_SUPPLICANT_DIR}" -j8 eapol_test 1>&2 || [ ! -e "${WPA_SUPPLICANT_DIR}/eapol_test" ]; then
    echo "Build error" 1>&2
    if [ -z "${BUILD_DIR}" ]; then rm -rf "$TMP_BUILD_DIR"; fi
    exit 1
fi

cp "${WPA_SUPPLICANT_DIR}/eapol_test" "${EAPOL_TEST_PATH}"

echo "${EAPOL_TEST_PATH}"
if [ -z "${BUILD_DIR}" ]; then rm -rf "$TMP_BUILD_DIR"; fi

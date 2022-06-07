#!/usr/bin/env bash

declare readonly CURDIR=$(cd $(dirname ${BASH_SOURCE[0]}); pwd -L)
declare readonly BUILDDIR=bin
declare readonly PKG_CONFIG_PATHS=(
/usr/local/opt/openssl/lib/pkgconfig
)

function mksdir() {
    for d in "${@}"
    do
        if [[ ! -d ${d} ]]; then
            mkdir -p ${d}
        fi
    done
}

function mk_pkg_config_path() {
    for p in "${PKG_CONFIG_PATHS[@]}"
    do
        if [[ ! -d ${p} ]]; then
            continue
        fi
        if [[ -z ${PKG_CONFIG_PATH} ]]; then
            PKG_CONFIG_PATH=${p}
        else
            PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:${p}
        fi
    done
}

function main() {
    if pushd ${CURDIR} >& /dev/null; then
        # FIXME "build-aux" "m4" are defined inside configure.ac
        mksdir ${BUILDDIR} build-aux m4
        if [[ ! -f ./configure ]]; then
            if ! autoreconf -vi; then
                rm -f ./configure
                popd >& /dev/null
                return 1
            fi
        fi
        if [[ ! -f ${BUILDDIR}/Makefile ]]; then
            if pushd ${BUILDDIR} >& /dev/null; then
                mk_pkg_config_path
                if ! ../configure PKG_CONFIG_PATH=${PKG_CONFIG_PATH} "${@}"; then
                    rm -f Makefile
                fi
                popd >& /dev/null
            fi
        fi
        if command -v bear >& /dev/null; then
            bear --append -- make -C ${BUILDDIR} check "${@}"
        else
            make -C ${BUILDDIR} check "${@}"
        fi
        popd >& /dev/null
    fi
}

main "${@}"

#!/bin/bash
set -e

# NOTE: the images use `ENTRYPOINT ["pingwaf"]` and do not run this
# script; it stays for compose setups that override the entrypoint.
if [ "${1:0:1}" = '-' ]; then
    set -- pingwaf "$@"
fi

exec "$@"

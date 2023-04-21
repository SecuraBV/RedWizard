#!/usr/bin/env bash

set -e

if [ "$1" = "./teamserver" ] || [ "$1" = "./agscript" ]; then
    if /usr/bin/find "/docker-entrypoint.d/" -mindepth 1 -maxdepth 1 -type f -print -quit 2>/dev/null | read v; then
        echo >&2 "$0: /docker-entrypoint.d/ is not empty, will attempt to perform configuration"

        echo >&2 "$0: Looking for shell scripts in /docker-entrypoint.d/"
        find "/docker-entrypoint.d/" -follow -type f -print | sort -V | while read -r f; do
            case "$f" in
                *.sh)
                    if [ -x "$f" ]; then
                        echo >&2 "$0: Launching $f";
                        "$f"
                    else
                        # warn on shell scripts without exec bit
                        echo >&2 "$0: Ignoring $f, not executable";
                    fi
                    ;;
                *) echo >&2 "$0: Ignoring $f";;
            esac
        done

        echo >&2 "$0: Configuration complete; ready for start up"
    else
        echo >&2 "$0: No files found in /docker-entrypoint.d/, skipping configuration"
    fi
else
    echo >&2 "You haven't specified a command to run, please do so in docker-compose.yml by overriding the 'command' parameter"
fi

# Start the Cobalt Strike Teamserver with the IP of the redirector
exec "$@"

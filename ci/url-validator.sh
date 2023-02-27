#!/bin/bash

set -euo pipefail

grep -o -E "https?://[][[:alnum:]._~:/?@!$&'*+,;%=-]+" "$1" |
    while read line; do
        echo "Checking $line ... "
        # a lot of useless headers but some hosts such as
        # these protected by CloudFlare (cough, cough, crates.io)
        # don't like curl :-/
        curl -sSL --fail -I "$line" -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-User: ?1' > /dev/null
        echo OK
        sleep 1
    done

echo Done.

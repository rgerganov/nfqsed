[![Build Status](https://travis-ci.org/rgerganov/nfqsed.svg?branch=master)](https://travis-ci.org/rgerganov/nfqsed)

`nfqsed` is a command line utility that transparently modifies network traffic using a 
predefined set of substitution rules. It runs on Linux and uses the `netfilter_queue`
library. It is similar to `netsed` but it also allows modifying the network traffic 
passing through an ethernet bridge. This is especially useful in [situations][1] where the
source MAC address needs to stay unchanged.

Usage
--------
    nfqsed [-s /val1/val2] [-x /hex1/hex2] [-f file] [-v] [-q num]
        -s val1/val2     - replaces occurences of val1 with val2 in the packet payload
        -x hex1/hex2     - replaces occurences of hex1 with hex2 in the packet payload
        -f file          - read replacement rules from the specified file
        -q num           - bind to queue with number 'num' (default 0)
        -v               - be verbose

Example
-----------
Replace occurrences of _foo_ with _bar_ and occurrences of _good_ with _evil_ in all
forwarded packets that have destination port 554:

    # iptables -A FORWARD -p tcp --destination-port 554 -j NFQUEUE --queue-num 0
    # nfqsed -s /foo/bar -s /good/evil

Search and replace values can also be specified as hex strings where each hex byte is
zero padded. For example replacing `010203` with `414243`:

    # nfqsed -x /010203/414243

TODO
----
 * different lengths of val1 and val2

[1]: http://xakcop.com/post/mitm-stb/ 

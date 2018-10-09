:PREROUTING
*nat
-p ARP -i foo -j arpreply --arpreply-mac de:ad:0:be:ee:ff --arpreply-target ACCEPT;=;OK
-p ARP -i foo -j arpreply --arpreply-mac de:ad:0:be:ee:ff;=;OK

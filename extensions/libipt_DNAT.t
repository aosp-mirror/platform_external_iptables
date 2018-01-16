:PREROUTING
*nat
-j DNAT --to-destination 1.1.1.1;=;OK
-j DNAT --to-destination 1.1.1.1-1.1.1.10;=;OK
-j DNAT --to-destination 1.1.1.1:1025-65535;;FAIL
-p tcp -j DNAT --to-destination 1.1.1.1:1025-65535;=;OK
-p tcp -j DNAT --to-destination 1.1.1.1-1.1.1.10:1025-65535;=;OK
-p tcp -j DNAT --to-destination 1.1.1.1-1.1.1.10:1025-65536;;FAIL
-p tcp -j DNAT --to-destination 1.1.1.1-1.1.1.10:1025-65535 --to-destination 2.2.2.2-2.2.2.20:1025-65535;;FAIL
-j DNAT;;FAIL

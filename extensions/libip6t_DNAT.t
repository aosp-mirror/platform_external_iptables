:PREROUTING
*nat
-j DNAT --to-destination dead::beef;=;OK
-j DNAT --to-destination dead::beef-dead::fee7;=;OK
-j DNAT --to-destination [dead::beef]:1025-65535;;FAIL
-j DNAT --to-destination [dead::beef] --to-destination [dead::fee7];;FAIL
-p tcp -j DNAT --to-destination [dead::beef]:1025-65535;=;OK
-p tcp -j DNAT --to-destination [dead::beef-dead::fee7]:1025-65535;=;OK
-p tcp -j DNAT --to-destination [dead::beef-dead::fee7]:1025-65536;;FAIL
-p tcp -j DNAT --to-destination [dead::beef-dead::fee7]:1025-65535 --to-destination [dead::beef-dead::fee8]:1025-65535;;FAIL
-j DNAT;;FAIL

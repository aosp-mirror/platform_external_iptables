:INPUT,FORWARD,OUTPUT
-m mark --mark 0xfeedcafe/0xfeedcafe;=;OK
-m mark --mark 0x0;=;OK
-m mark --mark 4294967295;-m mark --mark 0xffffffff;OK
-m mark --mark 4294967296;;FAIL
-m mark --mark -1;;FAIL
-m mark;;FAIL
-s 1.2.0.0/15 -m mark --mark 0x0/0xff0;=;OK

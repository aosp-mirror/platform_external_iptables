:INPUT,FORWARD,OUTPUT
-s 0:0:0:0:0:0;=;OK
-d 00:00:0:00:00:00;-d 0:0:0:0:0:0;OK
-s de:ad:be:ef:0:00 -j RETURN;-s de:ad:be:ef:0:0 -j RETURN;OK
-d de:ad:be:ef:00:00 -j CONTINUE;=;OK
-d de:ad:be:ef:0:0;=;OK
-d de:ad:be:ef:00:00/ff:ff:ff:ff:00:00 -j DROP;-d de:ad:be:ef:0:0/ff:ff:ff:ff:0:0 -j DROP;OK

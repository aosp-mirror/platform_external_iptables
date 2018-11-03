:INPUT,FORWARD,OUTPUT
-d de:ad:be:ef:00:00;=;OK
-s 0:0:0:0:0:0;-s 00:00:00:00:00:00;OK
-d 00:00:00:00:00:00;=;OK
-s de:ad:be:ef:0:00 -j RETURN;-s de:ad:be:ef:00:00 -j RETURN;OK
-d de:ad:be:ef:00:00 -j CONTINUE;=;OK
-d de:ad:be:ef:0:00/ff:ff:ff:ff:0:0 -j DROP;-d de:ad:be:ef:00:00/ff:ff:ff:ff:00:00 -j DROP;OK

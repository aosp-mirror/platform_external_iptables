:INPUT,FORWARD,OUTPUT
-s 0:0:0:0:0:0;=;OK
-d 00:00:0:00:00:00;-d 0:0:0:0:0:0;OK
-s de:ad:be:ef:0:00 -j RETURN;-s de:ad:be:ef:0:0 -j RETURN;OK
-d de:ad:be:ef:0:0;=;OK
! --pkttype-type host;--pkttype-type ! host -j CONTINUE;OK
--pkttype-type host;=;OK
--pkttype-type broadcast;=;OK
--pkttype-type ! multicast;=;OK
--pkttype-type multicast;=;OK
--pkttype-type otherhost;=;OK
--pkttype-type outgoing;=;OK
--pkttype-type loopback;=;OK

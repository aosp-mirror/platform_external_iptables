:POSTROUTING
*nat
-o someport -j snat --to-source a:b:c:d:e:f;-o someport -j snat --to-src a:b:c:d:e:f --snat-target ACCEPT;OK
-o someport+ -j snat --to-src de:ad:0:be:ee:ff --snat-target CONTINUE;=;OK

:INPUT,FORWARD,OUTPUT
-p ip6 ! --ip6-src dead::beef/64 -j ACCEPT;-p IPv6 ! --ip6-src dead::/64 -j ACCEPT;OK
-p IPv6 --ip6-dst dead:beef::/64 -j ACCEPT;=;OK
-p IPv6 --ip6-dst f00:ba::;=;OK
-p IPv6 ! --ip6-dst f00:ba::;=;OK
-p IPv6 --ip6-src 10.0.0.1;;FAIL
-p IPv6 --ip6-tclass 0xFF;=;OK
-p IPv6 ! --ip6-tclass 0xFF;=;OK
-p IPv6 --ip6-proto tcp --ip6-dport 22;=;OK
-p IPv6 --ip6-proto tcp ! --ip6-dport 22;=;OK
-p IPv6 --ip6-proto tcp ! --ip6-sport 22 --ip6-dport 22;=;OK
-p IPv6 --ip6-proto udp --ip6-sport 1024:65535;=;OK
-p IPv6 --ip6-proto udp --ip6-sport :;-p IPv6 --ip6-proto udp --ip6-sport 0:65535;OK
-p IPv6 --ip6-proto udp --ip6-sport :4;-p IPv6 --ip6-proto udp --ip6-sport 0:4;OK
-p IPv6 --ip6-proto udp --ip6-sport 4:;-p IPv6 --ip6-proto udp --ip6-sport 4:65535;OK
-p IPv6 --ip6-proto udp --ip6-sport 3:4;=;OK
-p IPv6 --ip6-proto udp --ip6-sport 4:4;-p IPv6 --ip6-proto udp --ip6-sport 4;OK
-p IPv6 --ip6-proto udp --ip6-sport 4:3;;FAIL
-p IPv6 --ip6-proto udp --ip6-dport :;-p IPv6 --ip6-proto udp --ip6-dport 0:65535;OK
-p IPv6 --ip6-proto udp --ip6-dport :4;-p IPv6 --ip6-proto udp --ip6-dport 0:4;OK
-p IPv6 --ip6-proto udp --ip6-dport 4:;-p IPv6 --ip6-proto udp --ip6-dport 4:65535;OK
-p IPv6 --ip6-proto udp --ip6-dport 3:4;=;OK
-p IPv6 --ip6-proto udp --ip6-dport 4:4;-p IPv6 --ip6-proto udp --ip6-dport 4;OK
-p IPv6 --ip6-proto udp --ip6-dport 4:3;;FAIL
-p IPv6 --ip6-proto 253;=;OK
-p IPv6 ! --ip6-proto 253;=;OK
-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type echo-request -j CONTINUE;=;OK
-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type echo-request;=;OK
-p IPv6 --ip6-proto ipv6-icmp ! --ip6-icmp-type echo-request;=;OK
-p ip6 --ip6-protocol icmpv6 --ip6-icmp-type 1/1;-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type communication-prohibited -j CONTINUE;OK
-p IPv6 --ip6-proto ipv6-icmp ! --ip6-icmp-type 1:10/0:255;=;OK
--ip6-proto ipv6-icmp ! --ip6-icmp-type 1:10/0:255;=;FAIL
! -p IPv6 --ip6-proto ipv6-icmp ! --ip6-icmp-type 1:10/0:255;=;FAIL
-p IPv6 --ip6-proto tcp --ip6-sport 22 --ip6-icmp-type echo-request;;FAIL
-p IPv6 --ip6-proto tcp --ip6-dport 22 --ip6-icmp-type echo-request;;FAIL

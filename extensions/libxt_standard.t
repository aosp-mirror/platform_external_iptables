:INPUT,FORWARD,OUTPUT
-s 127.0.0.1/32 -d 0.0.0.0/8 -j DROP;=;OK
! -s 0.0.0.0 -j ACCEPT;! -s 0.0.0.0/32 -j ACCEPT;OK
! -d 0.0.0.0/32 -j ACCEPT;=;OK
-s 0.0.0.0/24 -j RETURN;=;OK
-p tcp -j ACCEPT;=;OK
! -p udp -j ACCEPT;=;OK
-j DROP;=;OK
-j ACCEPT;=;OK
-j RETURN;=;OK
! -p 0 -j ACCEPT;=;FAIL
-s 10.11.12.13/8;-s 10.0.0.0/8;OK
-s 10.11.12.13/9;-s 10.0.0.0/9;OK
-s 10.11.12.13/10;-s 10.0.0.0/10;OK
-s 10.11.12.13/11;-s 10.0.0.0/11;OK
-s 10.11.12.13/12;-s 10.0.0.0/12;OK
-s 10.11.12.13/30;-s 10.11.12.12/30;OK
-s 10.11.12.13/31;-s 10.11.12.12/31;OK
-s 10.11.12.13/32;-s 10.11.12.13/32;OK
-s 10.11.12.13/255.0.0.0;-s 10.0.0.0/8;OK
-s 10.11.12.13/255.128.0.0;-s 10.0.0.0/9;OK
-s 10.11.12.13/255.0.255.0;-s 10.0.12.0/255.0.255.0;OK
-s 10.11.12.13/255.0.12.0;-s 10.0.12.0/255.0.12.0;OK
:FORWARD
--protocol=tcp --source=1.2.3.4 --destination=5.6.7.8/32 --in-interface=eth0 --out-interface=eth1 --jump=ACCEPT;-s 1.2.3.4/32 -d 5.6.7.8/32 -i eth0 -o eth1 -p tcp -j ACCEPT;OK
-ptcp -s1.2.3.4 -d5.6.7.8/32 -ieth0 -oeth1 -jACCEPT;-s 1.2.3.4/32 -d 5.6.7.8/32 -i eth0 -o eth1 -p tcp -j ACCEPT;OK
-i + -d 1.2.3.4;-d 1.2.3.4/32;OK
-i + -p tcp;-p tcp;OK

:INPUT
-s 192.168.0.1;=;OK
-s 0.0.0.0/8;=;OK
-s ! 0.0.0.0;! -s 0.0.0.0;OK
-d 192.168.0.1;=;OK
! -d 0.0.0.0;=;OK
-d 0.0.0.0/24;=;OK
-j DROP -i lo;=;OK
-j ACCEPT ! -i lo;=;OK
-i ppp+;=;OK
! -i ppp+;=;OK
-i lo --destination-mac 11:22:33:44:55:66;-i lo --dst-mac 11:22:33:44:55:66;OK
--source-mac Unicast;--src-mac 00:00:00:00:00:00/01:00:00:00:00:00;OK
! --src-mac Multicast;! --src-mac 01:00:00:00:00:00/01:00:00:00:00:00;OK
--src-mac=01:02:03:04:05:06 --dst-mac=07:08:09:0A:0B:0C --h-length=6 --opcode=Request --h-type=Ethernet --proto-type=ipv4;--src-mac 01:02:03:04:05:06 --dst-mac 07:08:09:0a:0b:0c --opcode 1 --proto-type 0x800;OK
--src-mac ! 01:02:03:04:05:06 --dst-mac ! 07:08:09:0A:0B:0C --h-length ! 6 --opcode ! Request --h-type ! Ethernet --proto-type ! ipv4;! --src-mac 01:02:03:04:05:06 ! --dst-mac 07:08:09:0a:0b:0c ! --h-length 6 ! --opcode 1 ! --h-type 1 ! --proto-type 0x800;OK

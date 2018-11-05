:OUTPUT
-o lo --destination-mac 11:22:33:44:55:66;-o lo --dst-mac 11:22:33:44:55:66;OK
--dst-mac Broadcast ;--dst-mac ff:ff:ff:ff:ff:ff;OK
! -o eth+ -d 1.2.3.4/24 -j CLASSIFY --set-class 0000:0000;! -o eth+ -d 1.2.3.0/24 --h-length 6 --h-type 1 -j CLASSIFY --set-class 0000:0000;OK

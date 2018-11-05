:OUTPUT
-s 1.2.3.4 -j mangle --mangle-ip-s 1.2.3.5;-s 1.2.3.4 --h-length 6 --h-type 1 -j mangle --mangle-ip-s 1.2.3.5;OK
-d 1.2.3.4 -j mangle --mangle-ip-d 1.2.3.5;-d 1.2.3.4 --h-length 6 --h-type 1 -j mangle --mangle-ip-d 1.2.3.5;OK
-d 1.2.3.4 --h-length 6 --h-type 1 -j mangle --mangle-mac-d 00:01:02:03:04:05;=;OK
-d 1.2.3.4 -j mangle --mangle-mac-s 00:01:02:03:04:05;=;FAIL

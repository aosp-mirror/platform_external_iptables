:INPUT,OUTPUT
-d 0.0.0.0/8 -j MARK --set-mark 0x1;-d 0.0.0.0/8 --h-length 6 --h-type 1 -j MARK --set-xmark 0x1/0xffffffff;OK
-s ! 0.0.0.0 -j MARK --and-mark 0x17;! -s 0.0.0.0 --h-length 6 --h-type 1 -j MARK --set-xmark 0x0/0xffffffe8;OK
-s 0.0.0.0 -j MARK --or-mark 0x17;-s 0.0.0.0 --h-length 6 --h-type 1 -j MARK --set-xmark 0x17/0x17;OK

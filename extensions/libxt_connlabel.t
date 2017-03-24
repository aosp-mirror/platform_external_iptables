:INPUT,FORWARD,OUTPUT
# Backup the connlabel.conf, then add some label maps for test
@[ -f /etc/xtables/connlabel.conf ] && mv /etc/xtables/connlabel.conf /tmp/connlabel.conf.bak
@mkdir -p /etc/xtables
@echo "40 bit40" > /etc/xtables/connlabel.conf
@echo "41 bit41" >> /etc/xtables/connlabel.conf
@echo "128 bit128" >> /etc/xtables/connlabel.conf
-m connlabel --label "bit40";=;OK
-m connlabel ! --label "bit40";=;OK
-m connlabel --label "bit41" --set;=;OK
-m connlabel ! --label "bit41" --set;=;OK
-m connlabel --label "bit128";;FAIL
@echo > /etc/xtables/connlabel.conf
-m connlabel --label "abc";;FAIL
@rm -f /etc/xtables/connlabel.conf
-m connlabel --label "abc";;FAIL
# Restore the original connlabel.conf
@[ -f /tmp/connlabel.conf.bak ] && mv /tmp/connlabel.conf.bak /etc/xtables/connlabel.conf

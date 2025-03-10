:INPUT,FORWARD,OUTPUT
-m conntrack --ctstate NEW;=;OK
-m conntrack --ctstate NEW,ESTABLISHED;=;OK
-m conntrack --ctstate NEW,RELATED,ESTABLISHED;=;OK
-m conntrack --ctstate INVALID;=;OK
-m conntrack --ctstate UNTRACKED;=;OK
-m conntrack --ctstate SNAT,DNAT;=;OK
-m conntrack --ctstate wrong;;FAIL
# should we convert this to output "tcp" instead of 6?
-m conntrack --ctproto tcp;-m conntrack --ctproto 6;OK
-m conntrack --ctexpire 0;=;OK
-m conntrack --ctexpire 4294967295;=;OK
-m conntrack --ctexpire 0:4294967295;=;OK
-m conntrack --ctexpire 42949672956;;FAIL
-m conntrack --ctexpire -1;;FAIL
-m conntrack --ctexpire 3:3;-m conntrack --ctexpire 3;OK
-m conntrack --ctexpire 4:3;;FAIL
-m conntrack --ctdir ORIGINAL;=;OK
-m conntrack --ctdir REPLY;=;OK
-m conntrack --ctstatus NONE;=;OK
-m conntrack --ctstatus CONFIRMED;=;OK
-m conntrack --ctstatus ASSURED;=;OK
-m conntrack --ctstatus EXPECTED;=;OK
-m conntrack --ctstatus SEEN_REPLY;=;OK
-m conntrack;;FAIL
-m conntrack --ctproto 0;;FAIL
-m conntrack ! --ctproto 0;;FAIL
-m conntrack --ctorigsrcport :;-m conntrack --ctorigsrcport 0:65535;OK
-m conntrack --ctorigsrcport :4;-m conntrack --ctorigsrcport 0:4;OK
-m conntrack --ctorigsrcport 4:;-m conntrack --ctorigsrcport 4:65535;OK
-m conntrack --ctorigsrcport 3:4;=;OK
-m conntrack --ctorigsrcport 4:4;-m conntrack --ctorigsrcport 4;OK
-m conntrack --ctorigsrcport 4:3;;FAIL
-m conntrack --ctreplsrcport :;-m conntrack --ctreplsrcport 0:65535;OK
-m conntrack --ctreplsrcport :4;-m conntrack --ctreplsrcport 0:4;OK
-m conntrack --ctreplsrcport 4:;-m conntrack --ctreplsrcport 4:65535;OK
-m conntrack --ctreplsrcport 3:4;=;OK
-m conntrack --ctreplsrcport 4:4;-m conntrack --ctreplsrcport 4;OK
-m conntrack --ctreplsrcport 4:3;;FAIL
-m conntrack --ctorigdstport :;-m conntrack --ctorigdstport 0:65535;OK
-m conntrack --ctorigdstport :4;-m conntrack --ctorigdstport 0:4;OK
-m conntrack --ctorigdstport 4:;-m conntrack --ctorigdstport 4:65535;OK
-m conntrack --ctorigdstport 3:4;=;OK
-m conntrack --ctorigdstport 4:4;-m conntrack --ctorigdstport 4;OK
-m conntrack --ctorigdstport 4:3;;FAIL
-m conntrack --ctrepldstport :;-m conntrack --ctrepldstport 0:65535;OK
-m conntrack --ctrepldstport :4;-m conntrack --ctrepldstport 0:4;OK
-m conntrack --ctrepldstport 4:;-m conntrack --ctrepldstport 4:65535;OK
-m conntrack --ctrepldstport 3:4;=;OK
-m conntrack --ctrepldstport 4:4;-m conntrack --ctrepldstport 4;OK
-m conntrack --ctrepldstport 4:3;;FAIL

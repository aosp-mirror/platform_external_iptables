#!/bin/bash

#configuration
TESTDIR="./$(dirname $0)/"
RETURNCODE_SEPARATOR="_"
XTABLES_MULTI="$(dirname $0)/../../xtables-multi"
DIFF=$(which diff)

msg_error() {
        echo "E: $1 ..." >&2
        exit 1
}

msg_warn() {
        echo "W: $1" >&2
}

msg_info() {
        echo "I: $1"
}

if [ "$(id -u)" != "0" ] ; then
        msg_error "this requires root!"
fi

[ -z "$IPTABLES" ] && IPTABLES=$XTABLES_MULTI
if [ ! -x "$IPTABLES" ] ; then
        msg_error "no xtables-multi binary!"
else
        msg_info "using xtables-multi binary $IPTABLES"
fi

if [ ! -d "$TESTDIR" ] ; then
        msg_error "missing testdir $TESTDIR"
fi

FIND="$(which find)"
if [ ! -x "$FIND" ] ; then
        msg_error "no find binary found"
fi

MODPROBE="$(which modprobe)"
if [ ! -x "$MODPROBE" ] ; then
        msg_error "no modprobe binary found"
fi

DEPMOD="$(which depmod)"
if [ ! -x "$DEPMOD" ] ; then
        msg_error "no depmod binary found"
fi

if [ "$1" == "-v" ] ; then
        VERBOSE=y
        shift
fi

for arg in "$@"; do
        if grep ^.*${RETURNCODE_SEPARATOR}[0-9]\\+$ <<< $arg >/dev/null ; then
                SINGLE+=" $arg"
                VERBOSE=y
        else
                msg_error "unknown parameter '$arg'"
        fi
done

kernel_cleanup() {
	for it in iptables ip6tables; do
	for table in filter mangle nat raw; do
		$it -t $table -nL >/dev/null 2>&1 || continue # non-existing table
		$it -t $table -F        # delete rules
		$it -t $table -X        # delete custom chains
		$it -t $table -Z        # zero counters
	done
	done
	$DEPMOD -a
	$MODPROBE -raq \
	ip_tables iptable_nat iptable_mangle ipt_REJECT
}

find_tests() {
        if [ ! -z "$SINGLE" ] ; then
                echo $SINGLE
                return
        fi
        ${FIND} ${TESTDIR} -executable -regex \
                .*${RETURNCODE_SEPARATOR}[0-9]+ | sort
}


echo ""
ok=0
failed=0

for testfile in $(find_tests)
do

	for it in iptables ip6tables; do
		kernel_cleanup
		rc_spec=`echo $(basename ${testfile}) | cut -d _ -f2-`
		IPTABLES="$XTABLES_MULTI $it"

		msg_info "[EXECUTING]   $testfile"
		test_output=$(IPTABLES=$IPTABLES ${testfile} 2>&1)
		rc_got=$?
		echo -en "\033[1A\033[K" # clean the [EXECUTING] foobar line

		if [ "$rc_got" == "$rc_spec" ] ; then
			msg_info "[OK]          $testfile"
			[ "$VERBOSE" == "y" ] && [ ! -z "$test_output" ] && echo "$test_output"
			((ok++))

		else
			((failed++))
			if [ "$VERBOSE" == "y" ] ; then
				msg_warn "[FAILED]      $testfile: expected $rc_spec but got $rc_got"
				[ ! -z "$test_output" ] && echo "$test_output"
			else
				msg_warn "[FAILED]      $testfile"
			fi
		fi

	done
done

echo ""
msg_info "results: [OK] $ok [FAILED] $failed [TOTAL] $((ok+failed))"

kernel_cleanup
exit 0

#!/usr/bin/env python3
# encoding: utf-8

import os
import sys
import shlex
import argparse
from subprocess import Popen, PIPE

keywords = ("iptables-translate", "ip6tables-translate")


if sys.stdout.isatty():
    colors = {"magenta": "\033[95m", "green": "\033[92m", "yellow": "\033[93m",
              "red": "\033[91m", "end": "\033[0m"}
else:
    colors = {"magenta": "", "green": "", "yellow": "", "red": "", "end": ""}


def magenta(string):
    return colors["magenta"] + string + colors["end"]


def red(string):
    return colors["red"] + string + colors["end"]


def yellow(string):
    return colors["yellow"] + string + colors["end"]


def green(string):
    return colors["green"] + string + colors["end"]


def run_test(name, payload):
    test_passed = True
    result = []
    result.append(yellow("## " + name.replace(".txlate", "")))

    for line in payload:
        if line.startswith(keywords):
            process = Popen(shlex.split(line), stdout=PIPE, stderr=PIPE)
            (output, error) = process.communicate()
            if process.returncode == 0:
                translation = output.decode("utf-8").rstrip(" \n")
                expected = next(payload).rstrip(" \n")
                if translation != expected:
                    result.append(red("Fail"))
                    result.append(magenta("src: ") + line.rstrip(" \n"))
                    result.append(magenta("exp: ") + expected)
                    result.append(magenta("res: ") + translation + "\n")
                    test_passed = False
                elif args.all:
                    result.append(green("Ok"))
                    result.append(magenta("src: ") + line.rstrip(" \n"))
                    result.append(magenta("res: ") + translation + "\n")
            else:
                test_passed = False
                result.append(red("Error: ") + "iptables-translate failure")
                result.append(error.decode("utf-8"))

    if not test_passed or args.all:
        print("\n".join(result))


def load_test_files():
    for test in sorted(os.listdir("extensions")):
        if test.endswith(".txlate"):
            with open("extensions/" + test, "r") as payload:
                run_test(test, payload)


def main():
    if os.getuid() != 0:
        print(red("Error: ") + "You need to be root to run this, sorry")
    elif args.test:
        if not args.test.endswith(".txlate"):
            args.test += ".txlate"
        try:
            with open("extensions/" + args.test, "r") as payload:
                run_test(args.test, payload)
        except IOError:
            print(red("Error: ") + "test file does not exist")
    else:
        load_test_files()


parser = argparse.ArgumentParser()
parser.add_argument("--all", action="store_true", help="show also passed tests")
parser.add_argument("test", nargs="?", help="run only the specified test file")
args = parser.parse_args()
main()

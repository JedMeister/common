#!/usr/bin/python
# Copyright (c) 2010 Alon Swartz <alon@turnkeylinux.org>
"""Set account password
Arguments:
    username      username of account to set password for
Options:
    -p --pass=    if not provided, will ask interactively
"""

import sys
import getopt
import subprocess
from subprocess import PIPE
import signal

from executil import system

def fatal(s):
    print >> sys.stderr, "Error:", s
    sys.exit(1)

def usage(s=None):
    if s:
        print >> sys.stderr, "Error:", s
    print >> sys.stderr, "Syntax: %s <username> [options]" % sys.argv[0]
    print >> sys.stderr, __doc__
    sys.exit(1)

def main():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hp:", ['help', 'pass='])
    except getopt.GetoptError, e:
        usage(e)

    if len(args) != 1:
        usage()

    username = args[0]
    password = ""
    for opt, val in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-p', '--pass'):
            password = val

    if not password:
        from dialog_wrapper import Dialog
        d = Dialog('TurnKey GNU/Linux - First boot configuration')
        password = d.get_password(
            "%s Password" % username.capitalize(),
            "Please enter new password for the %s account." % username)


    command = ["chpasswd"]
    input = ":".join([username, password])

    p = subprocess.Popen(command, stdin=PIPE, shell=False)
    p.stdin.write(input)
    p.stdin.close()
    err = p.wait()
    if err:
        fatal(err)

    system("(echo \"{0}\" ; echo \"{0}\" ) | smbpasswd -a -s {1}".format(password,username))

if __name__ == "__main__":
    main()



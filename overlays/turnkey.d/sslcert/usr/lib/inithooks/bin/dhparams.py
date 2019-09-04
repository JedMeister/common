#!/usr/bin/python3

"""Select bit size to use when generating Diffie-Hellman (DH) parameters.
DH parameters define the DH key exchange[1] when creating an encrypted TLS
(e.g. HTTPS) connection to your server. 1024 is the minimum to protect against
attacks such as logjam. 2048 bits (or higher) is recommended, but can be quite
slow, especially on servers with limited (CPU) resources.

Options:

    --bitsize           1024 | 2048 | 4096

Note: options not specified but required by will be asked interactively

[1] https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange
"""

import sys
import argparse
from subprocess import run, Popen, PIPE, STDOUT

from dialog_wrapper import Dialog

def fatal(e):
    print("Error:", e, file=sys.stderr)
    sys.exit(1)

encoding = sys.stdin.encoding # assume stdin encoding is set correctly...

parser = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('-b', '--bitsize', choices={"1024", "2048", "4096"},
                    help="Diffie-Hellman parameters bit size")
args = parser.parse_args()

def main():
    dh_file = '/etc/ssl/private/dhparams.pem'

    try:
        bitsize = args.bitsize
    except ValueError:
        bitsize = ''

    dialog = Dialog('TurnKey Linux - First boot configuration')

    if not bitsize:
        bitsize = dialog.menu(
            "DH parameter bit size",
            "Select a bit size for the Diffie-Hellman (DH) parameter generation.\n\n"
            "This is used during initial key exchange when creating an encrypted "
            "TLS (aka SSL) connection with your server (e.g. HTTPS).\n\n"
            "(Larger is better, but can take a LONG time, especially when run "
            "on a server with low (CPU) resources",
            [
                ('1024', 'Recommended for low resource servers'),
                ('2048', 'General recommendation'),
                ('4096', 'For the more paranoid (warning: can take hours)')
            ])

    dh_gen = Popen(["openssl dhparam -out {} {}".format(
                   dh_file, bitsize)], stdout=PIPE, shell=True)
    while True:
        line = dh_gen.stdout.readline().rstrip()
        if not line:
            break
        print(line)
    if dh_gen.returncode:
        print('Error trying to create DH params file.')
    exit
    chmod = run(['chmod', '400', dh_file], stderr=PIPE)
    if chmod.returncode != 0:
        fatal(chmod.stderr.decode(encoding))

if __name__ == "__main__":
    main()

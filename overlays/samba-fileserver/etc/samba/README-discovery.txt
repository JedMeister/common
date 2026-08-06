TurnKey File Server - network discovery & NetBIOS/WINS
======================================================

Modern clients (Windows 10/11, macOS, Linux) discover this server using:

  * WS-Discovery (wsdd)  - makes the server appear in Windows File
                           Explorer's "Network" view.
                           Ports: 5357/tcp, 3702/udp.
  * mDNS (avahi-daemon)  - discovery for macOS and Linux.  Port 5353/udp.

SMB/CIFS itself is served over port 445/tcp (and, unless disabled, the
legacy NetBIOS session port 139/tcp).

Connecting always works by IP:    \\<server-ip>\storage
...and by name if the name resolves via DNS / mDNS / LLMNR:
                                  \\<hostname>\storage


WINS server role (disabled)
---------------------------

This server no longer acts as a WINS server.  WINS only matters if you
have legacy NetBIOS clients configured (via DHCP option 44 or a manual
WINS address) to resolve NetBIOS names across subnets.  Local-subnet
NetBIOS name resolution and broadcast browsing still work while the nmbd
daemon is running.

To run this server as a WINS server again, edit /etc/samba/smb.conf and
add to the [global] section:

    wins support = yes
    dns proxy = no

then restart Samba:

    systemctl restart smbd nmbd

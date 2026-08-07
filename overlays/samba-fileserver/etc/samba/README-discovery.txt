TurnKey File Server - network discovery & NetBIOS/WINS
======================================================

Modern clients (Windows 10/11, macOS, Linux) discover this server using:

  * WS-Discovery (wsdd)  - makes the server appear in Windows File
                           Explorer's "Network" view.
                           Ports: 5357/tcp, 3702/udp.
  * mDNS (avahi-daemon)  - discovery for macOS and Linux.  Port 5353/udp.

SMB/CIFS is served over port 445/tcp only.

Connecting always works by IP:    \\<server-ip>\storage
...and by name if the name resolves via DNS / mDNS / LLMNR:
                                  \\<hostname>\storage


NetBIOS & WINS (disabled)
-------------------------

Legacy NetBIOS (the nmbd daemon, ports 137-139) and the WINS server role
are disabled.  Modern clients do not need them.  You only need NetBIOS for
pre-Windows-10 clients, or anything that locates the server by NetBIOS
name resolution / broadcast browsing rather than DNS / mDNS.

To re-enable NetBIOS (and, optionally, the WINS server role):

  1. Edit /etc/samba/smb.conf and, in the [global] section, remove (or
     comment out) these two lines:

         disable netbios = yes
         smb ports = 445

     To also run a WINS server, add:

         wins support = yes
         dns proxy = no

  2. Re-enable and start the NetBIOS daemon, and reload smbd:

         systemctl enable --now nmbd
         systemctl restart smbd

  3. Open the firewall ports - in Webmin (Networking > Linux Firewall) or
     via iptables: 139/tcp and 137-138/udp.  They are closed by default on
     this appliance.

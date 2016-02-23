[![Build Status](https://travis-ci.org/CERN-CERT/activity_klog.svg?branch=master)](https://travis-ci.org/CERN-CERT/activity_klog)
# Activity_Klog: Kernel modules for logging various user activity

This project contains a collection of Linux loadable kernel modules aimed to logs any user action:
- Secure_Log: Provides a ring buffer separated from the standard kernel one, intended to contain all logged activity
- Execlog: Logs all calls to the 'execve' syscall, effectively tracking all users executions
- Netlog: Logs TCP/UDP high lever activity via the following syscalls:
 - TCP connect: inet_stream_connect
 - UDP 'connect': inet_dgram_connect
 - TCP accept: sys_accept(4)
 - UDP/TCP close: sys_close
 - UDP bind: sys_bind

For any action loged, the user and group ids, the effective user and group ids, the process, session and parent ids, the tty corresponding to the action are also logged, allowing administrators to trace back any activity to the user responsible.

##  Linux integration

The Execlog and Netlog modules uses the Kprobe API, the same Linux kernel API as the one used by systemtap.
By putting probes on some specific kernel functions, these modules are able to collect the information they need without impacting too much the normal behavior of the Linux Kernel.

## How to compile/use

- Install GCC and the linux headers on your system
- Run make inside the 'src' folder
- Run, inside the 'src' folder, 'insmod secure_log/secure_log.ko; insmod execlog/execlog.ko; insmod netlog/netlog.ko'

The modules can also be installed to the standard location using 'make install'.
For distribution integration, please look at 'activity_klog.spec'.

## Compatibility mode

While version 2 introduces a secure_log device, it's possible to keep the logs in dmesg as in version 1
This compatibility version is the one used on Scientific Linux CERN 6 while the new version is used on Centos CERN 7.

In order to enable this feature, please look inside the spec file or:
- Add "ccflags-y += -DUSE_PRINK=1" to execlog/Kbuild and netlog/Kbuild
- Add "print_netlog.c" to the list of source files in netlog/Kbuild

## Netlog configuration

Netlog is a highly configurable module. All its configuration is accessible via kernel parameters:
- whitelist: A comma-separated list of processes/ips/ports that should not be logged (see bellow)
- probe_tcp_connect: controls the monitoring of TCP connect, set to 1 for enabling it
- probe_tcp_accept: controls the monitoring of TCP accept, set to 1 for enabling it
- probe_tcp_close: controls the monitoring of TCP close, set to 1 for enabling it
- probe_udp_connect: controls the monitoring of UDP connect, set to 1 for enabling it
- probe_tcp_bind: controls the monitoring of UDP bind, set to 1 for enabling it
- probe_udp_close: controls the monitoring of UDP close, set to 1 for enabling it
- probes: mask for probes to be set: 0 set none, 0xffff sets all

### Netlog whitelist

netlog offers a whitelist system, which will ignore the whitelisted actions before they are logged.
In order to be used, the module needs to be compiled with WHITELISTING set to 1 in netlog/netlog.h.
This feature is controled by the 'whitelist' parameter and can be set at load time (by specifying it when loading the module) or at run time (by changing the content of /sys/module/netlog/parameters/whitelist)

The whitelist itself is a coma-separated list, containing the binary path, the remote IP address (IPv4 or IPv6) and the remote port in the following format: "${/path/to/binary/}|i${remote_ip}|p${remote_port}".
The remote IP and/or the remote port can be ommited, in which case any remote IP/port will be ignored. For example:
- "/usr/sbin/sshd|i<127.0.0.1>|p<22>": Connections from/to port 22 on IP 127.0.0.1 handled by /usr/sbin/sshd will be ignored
- "/usr/sbin/sshd|i<127.0.0.1>": Connections from/to IP 127.0.0.1 handled by /usr/sbin/sshd will be ignored
- "/usr/sbin/sshd|p<22>": Connections from/to port 22 handled by /usr/sbin/sshd will be ignored
- "/usr/sbin/sshd": Connections handled by /usr/sbin/sshd will be ignored

Warning: Changing the whitelist live requires a write lock on all netlog probes, blocking all corresponding syscalls while the new whitelist is installed.

## Licence

Copyright 2011-2015 CERN.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

In applying this licence, CERN does not waive the privileges and immunities granted to it by virtue of its status as an Intergovernmental Organization or submit itself to any jurisdiction.

You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>. This software is distributed under the terms of the GNU General PublicLicence version 3 (GPL Version 3), copied verbatim in the file COPYING. 

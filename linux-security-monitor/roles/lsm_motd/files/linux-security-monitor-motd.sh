#!/usr/bin/env bash
set -u
HOSTNAME=$(hostname)
OS=$(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release)
KERNEL=$(uname -r)
ARCH=$(uname -m)
LOAD=$(awk '{print $1}' /proc/loadavg)
PROCESSES=$(ps -e --no-headers | wc -l)
DISK=$(df -h / | awk 'NR==2 {print $5 " de " $2}')
MEMORY=$(free | awk '/Mem:/ {if ($2 > 0) printf "%.0f%%", ($2-$7)/$2*100; else print "N/A"}')
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')

cat <<EOF
============================================================
       SYSTEM MONITORED BY LINUX SECURITY MONITOR
============================================================

  Welcome to: $HOSTNAME

  Operating system: ${OS:-N/A}
  Kernel: $KERNEL
  Architecture: $ARCH

  System status:
  System load: $LOAD
  Processes: $PROCESSES
  Usage of /: $DISK
  Memory usage: $MEMORY
  IPv4 address: ${IP:-N/A}

============================================================
EOF

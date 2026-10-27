#!/usr/bin/env bash
set -uo pipefail

CPU_THRESHOLD=${1:-80}
MEM_THRESHOLD=${2:-50}
if ! [[ "$CPU_THRESHOLD" =~ ^[0-9]+([.][0-9]+)?$ && "$MEM_THRESHOLD" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo 'Los umbrales deben ser numéricos.' >&2
  exit 2
fi
printf '=== Linux Security Monitor ===\n'
printf 'Fecha: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf 'Umbrales: CPU > %s%% | Memoria > %s%%\n\n' "$CPU_THRESHOLD" "$MEM_THRESHOLD"

printf '%-8s %-8s %-12s %-8s %-8s %s\n' PID USER 'CPU(%)' 'MEM(%)' ESTADO PROCESO

alerts=0

while read -r pid user cpu mem command; do
  if awk -v c="$cpu" -v m="$mem" -v ct="$CPU_THRESHOLD" -v mt="$MEM_THRESHOLD" 'BEGIN { exit !(c > ct || m > mt) }'; then
    status=REVISAR
    ((alerts+=1))
  else
    status=OK
  fi
  printf '%-8s %-8s %-12s %-8s %-8s %s\n' "$pid" "$user" "$cpu" "$mem" "$status" "$command"
done < <(ps -eo pid=,user=,pcpu=,pmem=,comm= --sort=-%cpu)

printf '\nProcesos que superan los umbrales: %s\n' "$alerts"

(( alerts > 0 )) && exit 1
exit 0

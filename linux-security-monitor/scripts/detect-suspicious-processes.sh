#!/usr/bin/env bash
set -uo pipefail

CPU_THRESHOLD=80
MEM_THRESHOLD=50

printf '=== Linux Security Monitor ===\n'
printf 'Fecha: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf 'Umbrales: CPU > %s%% | Memoria > %s%%\n\n' \
  "$CPU_THRESHOLD" "$MEM_THRESHOLD"

printf '%-8s %-8s %-12s %-8s %-8s %s\n' \
  "PID" "USER" "CPU(%)" "MEM(%)" "ESTADO" "PROCESO"

alerts=0

while read -r pid user cpu mem command; do
  [[ "$pid" == "PID" ]] && continue

  if [[ "$cpu" =~ ^[0-9]+([.][0-9]+)?$ ]] &&
     [[ "$mem" =~ ^[0-9]+([.][0-9]+)?$ ]]; then

    status="OK"

    if awk -v c="$cpu" -v m="$mem" \
      'BEGIN { exit !(c > 80 || m > 50) }'; then
      status="REVISAR"
      ((alerts+=1))
    fi

    printf '%-8s %-8s %-12s %-8s %-8s %s\n' \
      "$pid" "$user" "$cpu" "$mem" "$status" "$command"
  fi
done < <(ps -eo pid=,user=,pcpu=,pmem=,comm= --sort=-%cpu)

printf '\nProcesos que superan los umbrales: %s\n' "$alerts"

if (( alerts > 0 )); then
  exit 1
fi

exit 0

#!/usr/bin/env bash
set -euo pipefail
INCLUDE_PROCESSES=${1:-yes}
[[ "$INCLUDE_PROCESSES" == yes || "$INCLUDE_PROCESSES" == no ]] || { echo 'include_processes debe ser yes/no' >&2; exit 2; }
printf '%s\n' '=== Linux Security Monitor: Red ==='
printf 'Fecha: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S')"

printf '%s\n' '=== Interfaces de red ==='
ip -brief address
printf '\n%s\n' '=== Puertos en escucha ==='
if [[ "$INCLUDE_PROCESSES" == yes ]]; then ss -lntup; else ss -lntu; fi
printf '\n%s\n' '=== Conexiones TCP/UDP ==='
if [[ "$INCLUDE_PROCESSES" == yes ]]; then ss -tunap; else ss -tuna; fi
printf '\n%s\n' '=== Fin del informe ==='

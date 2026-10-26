#!/usr/bin/env bash
set -uo pipefail

printf '%s\n' '=== Linux Security Monitor: Red ==='
printf 'Fecha: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S')"

printf '%s\n' '=== Interfaces de red ==='
ip -brief address
printf '\n'

printf '%s\n' '=== Puertos en escucha ==='
ss -lntup
printf '\n'

printf '%s\n' '=== Conexiones TCP/UDP ==='
ss -tunap
printf '\n'

printf '%s\n' '=== Fin del informe ==='

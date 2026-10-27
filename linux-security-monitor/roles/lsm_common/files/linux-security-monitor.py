#!/usr/bin/env python3
"""Run the installed Linux Security Monitor modules locally."""
import argparse
import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

CONFIG = Path('/etc/linux-security-monitor/config.json')
INTEGRITY = Path('/usr/local/lib/linux-security-monitor/integrity.py')
PROCESS = Path('/usr/local/lib/linux-security-monitor/detect-suspicious-processes.sh')
NETWORK = Path('/usr/local/lib/linux-security-monitor/collect-network-connections.sh')


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d_%H-%M-%S-%f')


def generated_at() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def load_config() -> dict:
    try:
        data = json.loads(CONFIG.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f'No se puede leer la configuración {CONFIG}: {exc}') from exc
    if not isinstance(data, dict):
        raise RuntimeError(f'Configuración inválida: {CONFIG}')
    return data


def run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def report_directory(config: dict, category: str) -> Path:
    reports = Path(config['reports_dir'])
    reports.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(reports, 0o700)
    module_reports = reports / category
    module_reports.mkdir(mode=0o700, exist_ok=True)
    os.chmod(module_reports, 0o700)
    return module_reports


def save_report(config: dict, category: str, content: str, filename_prefix: str | None = None, stamp: str | None = None) -> Path:
    stamp = stamp or timestamp()
    path = report_directory(config, category) / f'{filename_prefix or category}_{stamp}.txt'
    path.write_text(content.rstrip() + '\n')
    os.chmod(path, 0o600)
    return path


def save_json_report(config: dict, category: str, data: dict, filename_prefix: str | None = None, stamp: str | None = None) -> Path:
    stamp = stamp or timestamp()
    path = report_directory(config, category) / f'{filename_prefix or category}_{stamp}.json'
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    os.chmod(path, 0o600)
    return path


def report_data(module: str, status: str, summary: dict, findings: list[dict],
                metrics: dict[str, int | float] | None = None, **details: object) -> dict:
    return {
        'schema_version': 1,
        'module': module,
        'host': socket.gethostname(),
        'generated_at': generated_at(),
        'status': status,
        'summary': summary,
        'findings': findings,
        'metrics': metrics or {},
        **details,
    }


def require_enabled(config: dict, module: str) -> None:
    if not config.get('modules', {}).get(module, False):
        raise RuntimeError(f'El módulo {module} está deshabilitado en {CONFIG}.')


def integrity(config: dict, action: str) -> int:
    require_enabled(config, 'integrity')
    settings = config['integrity']
    baseline = settings['baseline_file']
    argv = [sys.executable, str(INTEGRITY), action, '--baseline', baseline,
            '--reports', config['reports_dir'], '--paths-json', json.dumps(settings['paths']),
            '--excludes-json', json.dumps(settings.get('excludes', []))]
    result = run(argv)
    if result.stdout:
        print(result.stdout, end='')
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='')
    return result.returncode


def processes(config: dict) -> int:
    require_enabled(config, 'processes')
    settings = config['processes']
    detected = run(['/bin/bash', str(PROCESS), str(settings['cpu_threshold']), str(settings['memory_threshold'])])
    listing = run(['/bin/ps', '-eo', 'pid,ppid,user,%cpu,%mem,lstart,args', '--sort=-%cpu'])
    if listing.returncode:
        raise RuntimeError(f'No se pudo recopilar la lista de procesos: {listing.stderr.strip()}')
    structured = run(['/bin/ps', '-eo', 'pid=,ppid=,user=,pcpu=,pmem=,comm=', '--sort=-%cpu'])
    if structured.returncode:
        raise RuntimeError(f'No se pudieron estructurar los procesos: {structured.stderr.strip()}')
    processes_found = []
    findings = []
    for line in structured.stdout.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            continue
        pid, ppid, user, cpu_text, memory_text, command = fields
        try:
            cpu, memory = float(cpu_text), float(memory_text)
        except ValueError:
            continue
        item = {'pid': int(pid), 'ppid': int(ppid), 'user': user, 'cpu_percent': cpu,
                'memory_percent': memory, 'command': command}
        processes_found.append(item)
        if cpu > float(settings['cpu_threshold']) or memory > float(settings['memory_threshold']):
            findings.append(item)
    status = 'error' if detected.returncode not in (0, 1) else ('alert' if detected.returncode == 1 or findings else 'ok')
    stamp = timestamp()
    report = save_report(config, 'processes', detected.stdout + ('\n' + detected.stderr if detected.stderr else ''), 'detection', stamp)
    save_json_report(config, 'processes', report_data(
        'processes', status,
        {'process_count': len(processes_found), 'alert_count': len(findings),
         'cpu_threshold': float(settings['cpu_threshold']), 'memory_threshold': float(settings['memory_threshold'])},
        findings,
        metrics={
            'lsm_processes_status_code': {'ok': 0, 'alert': 1, 'error': 2}[status],
            'lsm_processes_total': len(processes_found),
            'lsm_processes_alerts': len(findings),
            'lsm_processes_cpu_threshold_percent': float(settings['cpu_threshold']),
            'lsm_processes_memory_threshold_percent': float(settings['memory_threshold']),
            'lsm_processes_cpu_max_percent': max((p['cpu_percent'] for p in processes_found), default=0.0),
            'lsm_processes_memory_max_percent': max((p['memory_percent'] for p in processes_found), default=0.0),
        },
    ), 'detection', stamp)
    process_stamp = timestamp()
    save_report(config, 'processes', listing.stdout, 'processes', process_stamp)
    save_json_report(config, 'processes', report_data(
        'processes', 'ok', {'process_count': len(processes_found)}, [],
        metrics={
            'lsm_processes_total': len(processes_found),
            'lsm_processes_cpu_max_percent': max((p['cpu_percent'] for p in processes_found), default=0.0),
            'lsm_processes_memory_max_percent': max((p['memory_percent'] for p in processes_found), default=0.0),
        },
        report_type='process_list', processes=processes_found,
    ), 'processes', process_stamp)
    print(detected.stdout, end='')
    print(f'Informe: {report}')
    return detected.returncode


def network(config: dict) -> int:
    require_enabled(config, 'network')
    include = 'yes' if config['network'].get('include_processes', True) else 'no'
    result = run(['/bin/bash', str(NETWORK), include])
    output = result.stdout + (('\nErrores:\n' + result.stderr) if result.stderr else '')
    ip_bin, ss_bin = shutil.which('ip'), shutil.which('ss')
    errors = []
    interfaces = []
    listening = []
    connections = []
    if not ip_bin or not ss_bin:
        errors.append('No se encontraron los comandos ip y/o ss.')
    else:
        ip_result = run([ip_bin, '-j', 'address', 'show'])
        if ip_result.returncode:
            errors.append(ip_result.stderr.strip() or 'ip no pudo obtener interfaces en JSON.')
        else:
            try:
                interfaces = json.loads(ip_result.stdout)
            except json.JSONDecodeError as exc:
                errors.append(f'La salida JSON de ip no es válida: {exc}')

        listen_flags = ['-H', '-lntup' if include == 'yes' else '-lntu']
        connection_flags = ['-H', '-tunap' if include == 'yes' else '-tuna']
        for command, flags, target in ((ss_bin, listen_flags, listening), (ss_bin, connection_flags, connections)):
            socket_result = run([command, *flags])
            if socket_result.returncode:
                errors.append(socket_result.stderr.strip() or f"ss falló con argumentos {' '.join(flags)}.")
                continue
            for line in socket_result.stdout.splitlines():
                fields = line.split(None, 6)
                if len(fields) < 6:
                    continue
                record = {
                    'protocol': fields[0], 'state': fields[1], 'receive_queue': fields[2],
                    'send_queue': fields[3], 'local_address': fields[4], 'peer_address': fields[5],
                }
                if len(fields) == 7:
                    record['process'] = fields[6]
                target.append(record)
    status = 'error' if result.returncode or errors else 'ok'
    active_interfaces = sum(1 for interface in interfaces if 'UP' in interface.get('flags', []))
    established_tcp = sum(1 for item in connections if item['protocol'] == 'tcp' and item['state'] == 'ESTAB')
    udp_sockets = sum(1 for item in connections if item['protocol'] == 'udp')
    stamp = timestamp()
    report = save_report(config, 'network', output, stamp=stamp)
    save_json_report(config, 'network', report_data(
        'network', status,
        {'interface_count': len(interfaces), 'listening_socket_count': len(listening),
         'connection_count': len(connections), 'include_processes': include == 'yes'},
        [], interfaces=interfaces, listening_sockets=listening, connections=connections, errors=errors,
        metrics={
            'lsm_network_status_code': {'ok': 0, 'alert': 1, 'error': 2}[status],
            'lsm_network_interfaces_total': len(interfaces),
            'lsm_network_interfaces_up': active_interfaces,
            'lsm_network_listening_sockets_total': len(listening),
            'lsm_network_sockets_total': len(connections),
            'lsm_network_tcp_established_total': established_tcp,
            'lsm_network_udp_sockets_total': udp_sockets,
            'lsm_network_collection_errors': len(errors),
            'lsm_network_process_details_enabled': int(include == 'yes'),
        },
    ), stamp=stamp)
    print(output, end='')
    print(f'Informe: {report}')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return result.returncode or 2
    return result.returncode


def antivirus(config: dict) -> int:
    require_enabled(config, 'antivirus')
    settings = config['antivirus']
    if settings.get('action', 'report') != 'report':
        raise RuntimeError('Solo se admite action=report; no se permite remediación automática.')
    clam = shutil.which('clamscan')
    if not clam:
        raise RuntimeError('No se encontró clamscan; reinstale el módulo antivirus con Ansible.')
    output: list[str] = []
    signature_result = None
    if settings.get('update_signatures', True):
        freshclam = shutil.which('freshclam')
        if not freshclam:
            raise RuntimeError('No se encontró freshclam; reinstale el módulo antivirus con Ansible.')
        signature_result = run([freshclam])
        output.extend(['=== Actualización de firmas ===', signature_result.stdout, signature_result.stderr])
        if signature_result.returncode:
            content = '\n'.join(output)
            stamp = timestamp()
            report = save_report(config, 'antivirus', content, stamp=stamp)
            save_json_report(config, 'antivirus', report_data(
                'antivirus', 'error', {'scanned_files': 0, 'infected_files': 0}, [],
                metrics={
                    'lsm_antivirus_status_code': 2,
                    'lsm_antivirus_scanned_files': 0,
                    'lsm_antivirus_infected_files': 0,
                    'lsm_antivirus_signatures_updated': 0,
                    'lsm_antivirus_scan_completed': 0,
                },
                signatures_updated=False,
                signature_update_exit_code=signature_result.returncode,
                errors=[signature_result.stderr.strip() or signature_result.stdout.strip()],
            ), stamp=stamp)
            print(content)
            print(f'Informe: {report}')
            return signature_result.returncode
    excludes = [f'--exclude={pattern}' for pattern in settings.get('excludes', [])]
    scan = run([clam, *settings.get('extra_args', []), *excludes, *settings['paths']])
    output.extend(['=== Escaneo ClamAV ===', scan.stdout, scan.stderr, f'Código ClamAV: {scan.returncode}'])
    content = '\n'.join(output)
    findings = []
    for line in scan.stdout.splitlines():
        if line.endswith(' FOUND') and ': ' in line:
            path, signature = line.rsplit(': ', 1)
            findings.append({'path': path, 'signature': signature.removesuffix(' FOUND')})
    scanned_match = re.search(r'^Scanned files:\s*(\d+)', scan.stdout, re.MULTILINE)
    infected_match = re.search(r'^Infected files:\s*(\d+)', scan.stdout, re.MULTILINE)
    scanned_count = int(scanned_match.group(1)) if scanned_match else None
    infected_count = int(infected_match.group(1)) if infected_match else len(findings)
    status = 'error' if scan.returncode > 1 else ('alert' if scan.returncode == 1 or findings else 'ok')
    stamp = timestamp()
    report = save_report(config, 'antivirus', content, stamp=stamp)
    save_json_report(config, 'antivirus', report_data(
        'antivirus', status,
        {'scanned_files': scanned_count, 'infected_files': infected_count}, findings,
        metrics={
            'lsm_antivirus_status_code': {'ok': 0, 'alert': 1, 'error': 2}[status],
            'lsm_antivirus_scanned_files': scanned_count or 0,
            'lsm_antivirus_scanned_files_known': int(scanned_count is not None),
            'lsm_antivirus_infected_files': infected_count,
            'lsm_antivirus_signatures_updated': int(signature_result is None or signature_result.returncode == 0),
            'lsm_antivirus_scan_completed': int(scan.returncode in (0, 1)),
        },
        signatures_updated=(signature_result is None or signature_result.returncode == 0),
        scan_exit_code=scan.returncode,
        errors=[scan.stderr.strip()] if scan.returncode > 1 and scan.stderr.strip() else [],
    ), stamp=stamp)
    print(content)
    print(f'Informe: {report}')
    return scan.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description='Linux Security Monitor local')
    parser.add_argument('module', choices=['all', 'antivirus', 'integrity', 'processes', 'network'])
    parser.add_argument('integrity_action', nargs='?', choices=['create', 'check'])
    args = parser.parse_args()
    config = load_config()
    if args.module == 'integrity':
        action = args.integrity_action or 'check'
        return integrity(config, action)
    if args.integrity_action:
        parser.error('La acción create/check solo aplica a integrity.')
    actions = {'antivirus': antivirus, 'processes': processes, 'network': network}
    if args.module != 'all':
        return actions[args.module](config)
    results = []
    for name, function in actions.items():
        if config.get('modules', {}).get(name, False):
            results.append((name, function(config)))
    if config.get('modules', {}).get('integrity', False):
        results.append(('integrity', integrity(config, 'check')))
    failures = [(name, code) for name, code in results if code]
    if failures:
        print(f'Hay módulos con alertas o errores: {failures}', file=sys.stderr)
        return max(code for _, code in failures)
    print('Módulos habilitados completados sin alertas.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(2)

#!/usr/bin/env python3
"""Create and verify per-host SHA-256 file integrity baselines."""
import argparse
import fnmatch
import hashlib
import json
import os
import socket
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


def excluded(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) or Path(path).match(pattern) for pattern in patterns)


def collect(paths: list[str], patterns: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    errors: list[str] = []
    for configured in paths:
        root = Path(configured)
        if not root.exists():
            errors.append(f"ruta inexistente: {configured}")
            continue
        entries = [root] if root.is_file() else sorted(root.rglob('*'))
        if root.is_dir():
            entries.insert(0, root)
        for entry in entries:
            name = str(entry)
            if excluded(name, patterns):
                continue
            try:
                mode = entry.stat().st_mode
                if stat.S_ISREG(mode):
                    digest = hashlib.sha256()
                    with entry.open('rb') as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(chunk)
                    found[name] = digest.hexdigest()
                elif not (stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                    continue
            except OSError as exc:
                errors.append(f"sin permisos/ error leyendo {name}: {exc}")
    if errors:
        raise RuntimeError('\n'.join(errors))
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['create', 'check'])
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--reports', required=True)
    parser.add_argument('--paths-json', required=True)
    parser.add_argument('--excludes-json', default='[]')
    args = parser.parse_args()
    paths = json.loads(args.paths_json)
    patterns = json.loads(args.excludes_json)
    if not isinstance(paths, list) or not paths or any(not isinstance(p, str) or not p.startswith('/') for p in paths):
        parser.error('paths debe ser una lista no vacía de rutas absolutas')
    if not isinstance(patterns, list) or any(not isinstance(p, str) for p in patterns):
        parser.error('excludes debe ser una lista de patrones')
    baseline, reports = Path(args.baseline), Path(args.reports)
    baseline.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reports.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(baseline.parent, 0o700)
    os.chmod(reports, 0o700)
    reports = reports / 'integrity'
    reports.mkdir(mode=0o700, exist_ok=True)
    os.chmod(reports, 0o700)
    current = collect(paths, patterns)
    if args.action == 'create':
        baseline.write_text(json.dumps({'algorithm': 'sha256', 'files': current}, indent=2) + '\n')
        os.chmod(baseline, 0o600)
        result, code = [f'Baseline creada: {len(current)} archivos; {baseline}'], 0
        status = 'ok'
        findings = []
        summary = {'scanned_files': len(current), 'baseline_files': len(current)}
        metrics = {
            'lsm_integrity_status_code': 0,
            'lsm_integrity_files_scanned': len(current),
            'lsm_integrity_baseline_files': len(current),
            'lsm_integrity_files_modified': 0,
            'lsm_integrity_files_deleted': 0,
            'lsm_integrity_files_new': 0,
            'lsm_integrity_baseline_created': 1,
        }
        event = 'baseline_created'
    else:
        if not baseline.is_file():
            raise RuntimeError(f'no existe la baseline: {baseline}; ejecute con --tags baseline')
        saved = json.loads(baseline.read_text())
        if saved.get('algorithm') != 'sha256' or not isinstance(saved.get('files'), dict):
            raise RuntimeError(f'baseline inválida: {baseline}')
        previous = saved['files']
        changed = sorted(path for path in current.keys() & previous.keys() if current[path] != previous[path])
        deleted = sorted(previous.keys() - current.keys())
        added = sorted(current.keys() - previous.keys())
        result = [f'Modificados: {changed or "ninguno"}', f'Eliminados: {deleted or "ninguno"}', f'Nuevos: {added or "ninguno"}']
        code = 2 if changed or deleted else 0
        status = 'alert' if changed or deleted else 'ok'
        findings = (
            [{'type': 'modified', 'path': path, 'baseline_sha256': previous[path], 'current_sha256': current[path]} for path in changed]
            + [{'type': 'deleted', 'path': path, 'baseline_sha256': previous[path]} for path in deleted]
            + [{'type': 'new', 'path': path, 'current_sha256': current[path]} for path in added]
        )
        summary = {'scanned_files': len(current), 'modified_count': len(changed),
                   'deleted_count': len(deleted), 'new_count': len(added)}
        metrics = {
            'lsm_integrity_status_code': 1 if changed or deleted else 0,
            'lsm_integrity_files_scanned': len(current),
            'lsm_integrity_baseline_files': len(previous),
            'lsm_integrity_files_modified': len(changed),
            'lsm_integrity_files_deleted': len(deleted),
            'lsm_integrity_files_new': len(added),
            'lsm_integrity_baseline_created': 0,
        }
        event = 'integrity_check'
    now = datetime.now(timezone.utc)
    stamp = now.strftime('%Y-%m-%d_%H-%M-%S-%f')
    report = reports / f'integrity_{stamp}.txt'
    report.write_text('\n'.join([f'Fecha UTC: {now.isoformat()}', *result]) + '\n')
    os.chmod(report, 0o600)
    json_report = reports / f'integrity_{stamp}.json'
    json_report.write_text(json.dumps({
        'schema_version': 1,
        'module': 'integrity',
        'host': socket.gethostname(),
        'generated_at': now.isoformat().replace('+00:00', 'Z'),
        'status': status,
        'event': event,
        'baseline': str(baseline),
        'paths': paths,
        'excludes': patterns,
        'summary': summary,
        'metrics': metrics,
        'findings': findings,
    }, indent=2, ensure_ascii=False) + '\n')
    os.chmod(json_report, 0o600)
    print('\n'.join([*result, f'Informe: {report}', f'JSON: {json_report}']))
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f'ERROR de integridad: {exc}', file=sys.stderr)
        sys.exit(1)

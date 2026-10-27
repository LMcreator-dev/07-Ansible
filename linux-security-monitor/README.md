# Linux Security Monitor

Este proyecto instala y ejecuta controles de seguridad en el mismo servidor donde está la copia. Ansible usa `localhost`; no necesita conectarse a otras IP.

## Organización

`site.yml` es la entrada principal. `inventory/host_vars/` contiene la configuración de cada hostname. En `roles/`, cada módulo guarda sus tareas en `tasks/`, sus valores por defecto en `defaults/` y los scripts que instala en `files/`; `lsm_common` también contiene el ejecutable local y la plantilla de configuración. Solo aparecen las carpetas que cada rol necesita.

## Qué hace `site.yml`

Al ejecutarlo, el playbook:

1. Lee `inventory/host_vars/<hostname>.yml`, usando el hostname corto del servidor (`hostname -s`).
2. Comprueba la configuración y las rutas de los módulos activados.
3. Instala el monitor y los componentes que necesita cada módulo.
4. Crea la baseline SHA-256 si no existe; si ya existe, la conserva.
5. Ejecuta los módulos activados y guarda sus informes.

Si un análisis encuentra alertas o errores, guarda los informes y termina el playbook como fallido para que el resultado no pase inadvertido.

## Módulos

- **Antivirus:** usa ClamAV. Actualiza firmas con `freshclam` cuando está habilitado y analiza las rutas configuradas con `clamscan`. Solo informa: no elimina ni pone archivos en cuarentena.
- **Integridad:** compara SHA-256 con una baseline. Informa de archivos modificados, eliminados y nuevos. Crear una baseline nueva es explícito; el playbook solo crea la primera cuando falta.
- **Procesos:** recopila procesos y marca los que superan los límites de CPU o memoria definidos para el servidor.
- **Red:** recoge interfaces, puertos y conexiones. Puede incluir la información de procesos que muestra `ss`.
- **MOTD:** instala el banner dinámico para los inicios de sesión SSH que usan `update-motd` con PAM. No sustituye `/etc/motd` ni modifica el mensaje de último acceso.

## Configuración por servidor

El inventario de `inventory/hosts.ini` apunta a la máquina local. `site.yml` obtiene su hostname y carga el archivo correspondiente de `inventory/host_vars/`. Si no existe, el playbook falla: crea uno con el mismo nombre que devuelve `hostname -s`.

En este servidor se usa `inventory/host_vars/devsecopssrv01.yml`. Ahora mismo activa integridad, procesos, red y MOTD; el antivirus está desactivado. Por eso `/var/tmp`, aunque figure como ruta antivirus, no se analiza hasta activar ese módulo.

Variables disponibles:

| Variable | Para qué sirve |
|---|---|
| `lsm_modules` | Activa o desactiva `antivirus`, `integrity`, `processes`, `network` y `motd`. |
| `lsm_reports_dir` | Ruta absoluta de informes. Por defecto es `reports/` dentro del proyecto; cada módulo tiene su subcarpeta. |
| `lsm_state_dir` | Estado persistente. Por defecto, `/var/lib/linux-security-monitor`. |
| `lsm_antivirus.paths` | Rutas absolutas que ClamAV analizará; debe tener al menos una ruta si el módulo está activo. |
| `lsm_antivirus.excludes` | Patrones excluidos del escaneo. |
| `lsm_antivirus.update_signatures` | Ejecuta `freshclam` antes del análisis. |
| `lsm_antivirus.action` | Debe ser `report`; no hay acciones automáticas sobre archivos. |
| `lsm_antivirus.extra_args` | Opciones admitidas: `--recursive`, `--follow-dir-symlinks` y `--follow-file-symlinks`. |
| `lsm_integrity.paths` | Rutas absolutas existentes que se recorrerán para calcular SHA-256. |
| `lsm_integrity.excludes` | Patrones de rutas excluidas de la baseline y de las comprobaciones. |
| `lsm_integrity.baseline_file` | Archivo JSON donde se guarda la baseline de este servidor. |
| `lsm_processes.cpu_threshold` | Umbral de CPU, entre 0 y 100. Se alerta si se supera. |
| `lsm_processes.memory_threshold` | Umbral de memoria, entre 0 y 100. Se alerta si se supera. |
| `lsm_network.include_processes` | Pide a `ss` que intente asociar sockets con procesos; requiere permisos adecuados. |

## Informes y baseline

Cada ejecución genera un `.txt` fácil de leer y un `.json` estructurado con el mismo nombre base. Se guardan por módulo:

```text
reports/
├── integrity/
├── processes/
├── network/
└── antivirus/   # se crea cuando se activa el antivirus
```

El JSON incluye versión del esquema, módulo, host, fecha UTC, estado (`ok`, `alert` o `error`), resumen, hallazgos y un objeto `metrics` con valores numéricos. Las métricas llevan nombres estables y unidades en su nombre cuando corresponde:

| Módulo | Métricas numéricas |
|---|---|
| Integridad | `lsm_integrity_status_code`, `lsm_integrity_files_scanned`, `lsm_integrity_baseline_files`, `lsm_integrity_files_modified`, `lsm_integrity_files_deleted`, `lsm_integrity_files_new`, `lsm_integrity_baseline_created`. |
| Procesos | `lsm_processes_status_code`, `lsm_processes_total`, `lsm_processes_alerts`, `lsm_processes_cpu_threshold_percent`, `lsm_processes_memory_threshold_percent`, `lsm_processes_cpu_max_percent`, `lsm_processes_memory_max_percent`. |
| Red | `lsm_network_status_code`, `lsm_network_interfaces_total`, `lsm_network_interfaces_up`, `lsm_network_listening_sockets_total`, `lsm_network_sockets_total`, `lsm_network_tcp_established_total`, `lsm_network_udp_sockets_total`, `lsm_network_collection_errors`, `lsm_network_process_details_enabled`. |
| Antivirus | `lsm_antivirus_status_code`, `lsm_antivirus_scanned_files`, `lsm_antivirus_scanned_files_known`, `lsm_antivirus_infected_files`, `lsm_antivirus_signatures_updated`, `lsm_antivirus_scan_completed`. |

Todos los módulos incluyen `lsm_<módulo>_status_code`: `0` significa correcto, `1` alerta y `2` error. El host y `generated_at` sirven para identificar la serie y el instante; los datos detallados siguen disponibles fuera de `metrics` (por ejemplo, procesos, interfaces, sockets y archivos afectados). Los JSON antiguos se actualizaron con métricas derivadas de sus datos existentes; los informes históricos en texto se conservaron.

Estos archivos ya contienen valores útiles para gráficas, pero **no publican una fuente de métricas por sí solos**. Para ver series en Grafana habrá que conectar más adelante una fuente o colector que lea estos JSON. El proyecto aún no instala ni configura esa integración.

Las carpetas de informes usan modo `0700` y los archivos modo `0600`. La baseline activa está en `/var/lib/linux-security-monitor/baselines/`, separada del código y de los informes. `/var/lib` es la ubicación habitual de Linux para datos persistentes de aplicaciones.

## Ejecutar

Desde la carpeta `linux-security-monitor/` de cada servidor:

```sh
hostname -s                         # comprueba el nombre del archivo host_vars
ansible-inventory --graph
ansible-playbook --syntax-check site.yml
ansible-playbook -K site.yml        # instala, crea baseline si falta y ejecuta módulos
```

Para ejecutar un único módulo con Ansible, por ejemplo red:

```sh
ansible-playbook -K site.yml -e lsm_selected_modules=network
```

Después de instalarlo, también puedes ejecutar módulos directamente en el servidor:

```sh
sudo linux-security-monitor integrity   # comprobar baseline
sudo linux-security-monitor processes
sudo linux-security-monitor network
sudo linux-security-monitor antivirus
sudo linux-security-monitor all         # todos los módulos de análisis activados
```

El MOTD se instala con Ansible y aparece al iniciar una sesión SSH; no se ejecuta con el comando `all`.

Si necesitas crear o renovar la baseline manualmente, usa `sudo linux-security-monitor integrity create`. Sobrescribe la baseline existente, así que ejecútalo solo cuando quieras establecer una referencia nueva.

## Requisitos y límites

Para instalar necesitas Ansible, Python 3 y permisos de `sudo`. Una vez instalado, puedes lanzar el monitor localmente sin Ansible. Los módulos de procesos y red usan `ps`, `ip` y `ss`; el MOTD también consulta `free`. ClamAV está configurado para Debian/Ubuntu y RedHat. El MOTD requiere el mecanismo `update-motd` de Debian/Ubuntu. Cada copia debe incluir `inventory/host_vars/<hostname>.yml` para su servidor.

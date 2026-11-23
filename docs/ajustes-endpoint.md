# Ajustes del endpoint Windows

Registro de todo lo que se instaló o modificó en el endpoint del laboratorio (`win10-host`), con el motivo, el valor anterior y la forma de revertirlo. El objetivo es que el estado del equipo sea **trazable y reversible**.

| Campo | Valor |
|---|---|
| Endpoint | `win10-host` (agente Wazuh `001`) |
| Sistema operativo | Windows 11 Pro, compilación 26300 |
| Rol | Equipo físico de uso personal que actúa como endpoint monitorizado |

> El documento de contexto inicial indicaba Windows 10 Pro. La versión real se comprobó con `Get-CimInstance Win32_OperatingSystem` durante la Fase 3.

---

## 1. Resumen

| # | Cambio | Tipo | Estado actual | Caso |
|---|---|---|---|---|
| 1 | Instalación de Sysmon 15.22 | Software | Instalado | Fase 3 |
| 2 | Instalación del agente de Wazuh 4.14.10 | Software | Instalado | Fase 3 |
| 3 | Lectura del canal de Sysmon en `ossec.conf` del agente | Configuración | Activo | Fase 3 |
| 4 | Servicio W32Time con inicio automático | Configuración | Activo | 1 |
| 5 | Sincronización horaria cada hora (`SpecialPollInterval`) | Registro | Activo | 1 / Fase 4 |
| 6 | Auditoría de "Otros eventos de acceso a objetos" (aciertos) | Política de auditoría | Activo | 3 |
| 7 | Frecuencia del FIM a 300 s | Configuración del agente | **Revertido** | 4 |

---

## 2. Software instalado

### 2.1 Sysmon

| Campo | Valor |
|---|---|
| Versión | 15.22 (binario firmado por Microsoft Corporation, firma verificada con `Get-AuthenticodeSignature`) |
| Ubicación de los archivos | `C:\Tools\Sysmon\` |
| Configuración | SwiftOnSecurity `sysmonconfig-export.xml`, versión 74 (2021-07-08), esquema 4.50 |
| Servicio | `Sysmon64`, inicio automático |
| Motivo | Telemetría detallada de procesos, red, archivos, registro y DNS, que el registro nativo de Windows no ofrece |

Instalación:

```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive .\Sysmon.zip -DestinationPath . -Force
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig-export.xml
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

**Revertir:**

```powershell
C:\Tools\Sysmon\Sysmon64.exe -u
```

### 2.2 Agente de Wazuh

| Campo | Valor |
|---|---|
| Versión | 4.14.10-1 (MSI firmado por Wazuh, Inc, firma verificada) |
| Ubicación | `C:\Program Files (x86)\ossec-agent\` |
| Servicio | `WazuhSvc`, inicio automático |
| Manager | `192.168.0.5` (puertos 1514/TCP y 1515/TCP) |
| Nombre del agente | `win10-host` (genérico, para no exponer el nombre real del equipo) |

Instalación (con ruta absoluta y log; el primer intento con ruta relativa falló sin mostrar ningún error):

```powershell
Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i "C:\Tools\Wazuh\wazuh-agent-4.14.10-1.msi" /q /l*v "C:\Tools\Wazuh\agent-install.log" WAZUH_MANAGER="192.168.0.5" WAZUH_AGENT_NAME="win10-host"'
```

**Revertir:** desinstalar "Wazuh Agent" desde *Configuración → Aplicaciones* (o con `msiexec /x` y el mismo MSI) y eliminar el agente `001` desde el dashboard o con `/var/ossec/bin/manage_agents` en el Manager.

---

## 3. Configuración del agente: lectura del canal de Sysmon

| Campo | Valor |
|---|---|
| Archivo | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| Copia de seguridad | `ossec.conf.bak` (antes del cambio) |
| Motivo | El agente no lee el canal de Sysmon por defecto |

Bloque añadido antes de `</ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Verificar:** el log del agente muestra `Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'`.

**Revertir:** eliminar el bloque (o restaurar `ossec.conf.bak`) y reiniciar el servicio `WazuhSvc`.

---

## 4. Sincronización horaria

### 4.1 Problema detectado

Durante el [Caso 1](casos/caso-01-autenticacion-fallida.md), el reloj del endpoint iba **16,3 s adelantado** respecto a la hora de referencia, porque el servicio W32Time estaba detenido. El desfase provocó dos hipótesis erróneas al correlacionar eventos con el Manager. Una semana después, con el servicio ya activo, el desfase había vuelto a crecer hasta **1,98 s**, porque Windows solo sincronizaba cada ~9 horas.

### 4.2 Servicio W32Time

| Campo | Antes | Después |
|---|---|---|
| Estado | `Stopped` | `Running` |
| Tipo de inicio | `Manual` | `Automatic` |

```powershell
Start-Service W32Time
Set-Service W32Time -StartupType Automatic
```

**Revertir:** `Set-Service W32Time -StartupType Manual`

### 4.3 Intervalo de sincronización

| Campo | Antes | Después |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient\SpecialPollInterval` | 32768 s (~9 h) | 3600 s (1 h) |

```powershell
$ruta = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
Set-ItemProperty -Path $ruta -Name SpecialPollInterval -Value 3600
Restart-Service W32Time
```

**Revertir:** `Set-ItemProperty -Path $ruta -Name SpecialPollInterval -Value 32768` y reiniciar W32Time.

**Resultado:** desfase de entre −0,005 s y +0,001 s respecto a `time.windows.com` tras el ajuste.

---

## 5. Política de auditoría: "Otros eventos de acceso a objetos"

| Campo | Valor |
|---|---|
| Subcategoría | Otros eventos de acceso a objetos (*Other Object Access Events*) |
| GUID | `{0CCE9227-69AE-11D9-BED3-505054503030}` |
| Antes | Sin auditoría |
| Después | Aciertos |
| Motivo | Sin ella no se generan los eventos 4698 (tarea creada) y 4699 (tarea eliminada), y la detección de tareas programadas es nula ([Caso 3](casos/caso-03-tarea-programada.md)) |
| Impacto | Volumen bajo de eventos adicionales en el registro de Seguridad |

```powershell
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable
```

> En un Windows en español, `auditpol` no reconoce los nombres de subcategoría en inglés. Usar el GUID evita el problema.

**Revertir:**

```powershell
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:disable
```

> La subcategoría "Inicio de sesión", necesaria para el evento 4625 del [Caso 1](casos/caso-01-autenticacion-fallida.md), ya estaba configurada en "Aciertos y errores" por defecto. No se modificó.

---

## 6. Cambio temporal: frecuencia del FIM (revertido)

| Campo | Valor |
|---|---|
| Archivo | `C:\Program Files (x86)\ossec-agent\ossec.conf`, bloque `<syscheck>` |
| Copia de seguridad | `ossec.conf.bak-fim` |
| Valor original | `<frequency>43200</frequency>` (12 h) |
| Valor durante la prueba | `<frequency>300</frequency>` (5 min) |
| Duración | ~17 minutos (2026-11-17, 16:19–16:36) |
| Motivo | Probar la detección del FIM de registro sin esperar 12 horas ([Caso 4](casos/caso-04-claves-run.md)) |

**Restauración aplicada y verificada:**

```powershell
Copy-Item "$conf.bak-fim" $conf -Force
Restart-Service WazuhSvc
```

Log del agente tras la restauración: `File integrity monitoring scan frequency: 43200 seconds`.

---

## 7. Artefactos de prueba eliminados

Todos los objetos creados durante las pruebas se eliminaron al terminar cada escenario:

| Artefacto | Escenario | Eliminación |
|---|---|---|
| Tareas `HomeSOCLab-E3`, `-cmd`, `-notepad`, `-benigna`, `-lolbin`, `-ruta` | 3 | `schtasks /delete` (confirmado por los eventos 4699) |
| Valores `HomeSOCLab-E4-*` en las claves `Run` de HKCU y HKLM | 4 | `Remove-ItemProperty`; comprobado con `Get-ItemProperty` |
| Archivo `C:\Users\Public\HomeSOCLab-E5.html` | 5 | `Remove-Item` |
| Conexiones SMB fallidas a `\\127.0.0.1\IPC$` (usuario inexistente) | 1 | No dejan artefactos |

**Comprobación rápida de que no queda nada:**

```powershell
schtasks /query /fo csv | Select-String 'HomeSOCLab'
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object -Property 'HomeSOCLab*'
Test-Path C:\Users\Public\HomeSOCLab-E5.html
```

Lo esperado es que los dos primeros comandos no devuelvan nada y que el tercero devuelva `False`.

---

## 8. Verificación del estado actual

```powershell
Get-Service Sysmon64, WazuhSvc, W32Time | Format-Table Name, Status, StartType
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient').SpecialPollInterval
auditpol /get /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}"
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern '<frequency>|Sysmon/Operational'
w32tm /stripchart /computer:time.windows.com /dataonly /samples:2
```

| Comprobación | Valor esperado |
|---|---|
| Servicios `Sysmon64`, `WazuhSvc`, `W32Time` | `Running`, `Automatic` |
| `SpecialPollInterval` | `3600` |
| Otros eventos de acceso a objetos | `Aciertos` |
| Frecuencia del FIM | `43200` |
| Canal de Sysmon en `ossec.conf` | Presente |
| Desfase horario | Inferior a 1 s |

---

## 9. Lo que no se modificó

- Microsoft Defender y el firewall de Windows conservan su configuración por defecto.
- No se crearon cuentas de usuario: las pruebas de autenticación usaron un usuario inexistente.
- No se desactivó ningún control de seguridad para facilitar las pruebas.
- No se ejecutó malware real; todas las pruebas usaron comandos benignos y destinos propios o reservados para pruebas (`example.com`).

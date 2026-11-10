# Caso 0 — Alertas generadas por el propio agente de Wazuh (módulo SCA)

| Campo | Valor |
|---|---|
| **Fecha** | 2026-11-09 |
| **Endpoint** | `win10-host` (agente `001`) — Windows 11 Pro, compilación 26300 |
| **Fuente de datos** | Sysmon 15.22 (configuración SwiftOnSecurity v74) → Wazuh Agent 4.14.10 → Wazuh Manager 4.14.10 |
| **Tipo de caso** | Investigación de alertas no provocadas (no forma parte de un escenario planificado) |
| **Clasificación final** | Verdadero positivo benigno (*Benign True Positive*) |
| **Estado** | Cerrado — ajuste de reglas pospuesto hasta observar un segundo ciclo de SCA |

---

## 1. Resumen

Minutos después de conectar el agente de Wazuh al Manager aparecieron **66 alertas** originadas en el canal de Sysmon del endpoint, algunas con descripciones alarmantes, como *"Powershell process created an executable file in Windows root folder"* (nivel 9).

La investigación demostró que toda la actividad la generó el **propio agente de Wazuh**: su módulo *Security Configuration Assessment* (SCA) ejecuta PowerShell, `SecEdit.exe` y `net user` para evaluar la política CIS de Windows 11, y su componente de respuesta activa reinicia el servicio mediante `net.exe`. Las reglas funcionaron correctamente, porque la conducta que vigilan ocurrió de verdad, pero la actividad era legítima.

---

## 2. Detección

Alertas del canal `Microsoft-Windows-Sysmon/Operational` registradas tras el primer arranque del agente:

| Regla | Nivel | Descripción | Alertas |
|---|---|---|---|
| 92205 | 9 | Powershell process created an executable file in Windows root folder | 20 |
| 92066 | 4 | `SecEdit.exe` binary in a suspicious location launched by `powershell.exe` | 16 |
| 92021 | 3 | Powershell was used to delete files or directories | 16 |
| 92031 | 3 | Discovery activity executed | 10 |
| 92052 | 4 | Windows command prompt started by an abnormal process | 2 |
| 92036 | 3 | A `net.exe` binary was started by a Windows cmd shell | 2 |
| **Total** | | | **66** |

Consulta utilizada en el Manager:

```bash
sudo grep "Microsoft-Windows-Sysmon" /var/ossec/logs/alerts/alerts.json \
  | jq -r '[.rule.id, .rule.level, .rule.description] | @tsv' \
  | sort | uniq -c | sort -rn
```

Consulta en el dashboard (*Threat Hunting → Events*):

```text
agent.name:win10-host and data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

![Alertas de Sysmon del endpoint en el dashboard de Wazuh](../../evidencias/caso-00/01-dashboard-alertas-sysmon.png)

---

## 3. Investigación

### 3.1 Observaciones iniciales

El detalle de una de las alertas (regla 92031, `net1 user`) ya ofrecía varios indicios:

| Campo | Valor | Interpretación |
|---|---|---|
| `data.win.eventdata.currentDirectory` | `C:\Program Files (x86)\ossec-agent\` | El proceso se ejecutó desde la carpeta del agente de Wazuh |
| `data.win.eventdata.parentUser` | `NT AUTHORITY\SYSTEM` | Lo lanzó un servicio, no un usuario interactivo |
| `data.win.eventdata.commandLine` | `C:\WINDOWS\system32\net1 user` | Enumeración de cuentas locales, típica de una auditoría de configuración |
| Hora | 16:38:12 – 16:38:30 | Coincide con el arranque del agente y el escaneo SCA registrado en `ossec.log` (16:38:15 – 16:38:34) |

![Detalle de la alerta de net1 user](../../evidencias/caso-00/02-detalle-alerta-net1.png)

### 3.2 Hipótesis

> Las alertas proceden del propio agente de Wazuh: el módulo SCA lanza comandos de auditoría que las reglas de Sysmon interpretan como actividad sospechosa.

### 3.3 Evidencia 1 — Archivos creados (regla 92205)

La regla 92205 se activa con el evento 11 de Sysmon (creación de archivos). Consulta en el Manager:

```bash
sudo jq -r 'select(.rule.id=="92205")
  | [.data.win.eventdata.image, .data.win.eventdata.targetFilename, .data.win.eventdata.user]
  | @tsv' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
```

Resultado (resumido; las 20 líneas siguen el mismo patrón):

```text
1  C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe  C:\Windows\SystemTemp\__PSScriptPolicyTest_<aleatorio>.ps1  NT AUTHORITY\SYSTEM
```

Los archivos `__PSScriptPolicyTest_*.ps1` los crea **PowerShell en cada arranque** para comprobar las políticas de ejecución de scripts. Como el proceso se ejecuta como SYSTEM, su carpeta temporal es `C:\Windows\SystemTemp`, que está dentro de `C:\Windows`, y eso activa la regla. Las 20 alertas corresponden a 20 ejecuciones de PowerShell.

### 3.4 Evidencia 2 — Árbol de procesos

Los eventos de creación de procesos (evento 1 de Sysmon) del minuto analizado se extrajeron en el propio endpoint:

```powershell
$ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1;
      StartTime=[datetime]'2026-11-09 16:38:00'; EndTime=[datetime]'2026-11-09 16:39:00'}
$ev | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [pscustomobject]@{ Hora = $_.TimeCreated.ToString('HH:mm:ss'); Proceso = Split-Path $d.Image -Leaf;
                     Padre = $d.ParentImage; Usuario = $d.User }
} | Where-Object { $_.Proceso -match 'powershell|cmd|net|secedit' } | Format-Table -AutoSize -Wrap
```

Resultado (extracto):

```text
Hora     Proceso        Padre                                                                     Usuario
----     -------        -----                                                                     -------
16:38:30 net.exe        C:\Program Files (x86)\ossec-agent\wazuh-agent.exe                        NT AUTHORITY\SYSTEM
16:38:29 powershell.exe C:\Program Files (x86)\ossec-agent\wazuh-agent.exe                        NT AUTHORITY\SYSTEM
16:38:29 SecEdit.exe    C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe                 NT AUTHORITY\SYSTEM
...
16:38:14 cmd.exe        C:\Program Files (x86)\ossec-agent\active-response\bin\restart-wazuh.exe  NT AUTHORITY\SYSTEM
16:38:14 net.exe        C:\Windows\SysWOW64\cmd.exe                                               NT AUTHORITY\SYSTEM
16:38:14 net1.exe       C:\Windows\SysWOW64\net.exe                                               NT AUTHORITY\SYSTEM
```

Árbol reconstruido:

```text
wazuh-agent.exe (SYSTEM)                          ← módulo SCA
├── powershell.exe ──► SecEdit.exe                → reglas 92066, 92021
│        └── crea __PSScriptPolicyTest_*.ps1      → regla 92205
└── net.exe ──► net1.exe user                     → reglas 92031, 92036

restart-wazuh.exe (SYSTEM)                        ← respuesta activa / reinicio del agente
└── cmd.exe ──► net.exe ──► net1.exe              → reglas 92052, 92036
```

**Todas las cadenas terminan en binarios del agente de Wazuh** ubicados en `C:\Program Files (x86)\ossec-agent\`. La hipótesis queda confirmada.

---

## 4. Conclusión

| Pregunta | Respuesta |
|---|---|
| ¿Ocurrió la conducta que describen las reglas? | Sí. PowerShell creó scripts dentro de `C:\Windows`, se ejecutó `SecEdit` y se enumeraron cuentas |
| ¿Fue maliciosa? | No. La originó el módulo SCA y el mecanismo de reinicio del propio agente |
| **Clasificación** | **Verdadero positivo benigno**: la regla acertó al detectar la conducta, pero la actividad es legítima |

Diferencia con un **falso positivo**: en un falso positivo la regla se equivoca, porque la conducta descrita no ocurrió. Aquí la conducta sí ocurrió, así que el problema no está en la regla sino en el contexto: la actividad es legítima.

---

## 5. Decisión sobre el ajuste de reglas

**No se crean exclusiones por ahora.** Motivos:

1. **Una sola observación no basta.** SCA se ejecuta por defecto cada 12 horas. Antes de ajustar nada hay que confirmar que el patrón se repite en el siguiente ciclo y medir cuántas alertas genera.
2. **Riesgo de crear un punto ciego.** Una exclusión amplia, como ignorar cualquier `powershell.exe` lanzado por SYSTEM, ocultaría también actividad maliciosa que se ejecute con esos mismos privilegios. Si se crea una exclusión, deberá ser lo más estrecha posible. Por ejemplo, para la regla 92205: solo el patrón `C:\Windows\SystemTemp\__PSScriptPolicyTest_*.ps1` y solo para el usuario SYSTEM.
3. **Las reglas de Sysmon solo ven al padre inmediato.** Para `SecEdit.exe` el padre es `powershell.exe`, no `wazuh-agent.exe`, así que no se puede excluir "lo que desciende del agente" con un único campo. Habría que identificar la línea de comandos exacta de PowerShell que utiliza SCA.

*Pendiente:* revisar el segundo ciclo de SCA y decidir.

---

## 6. Limitaciones y observaciones

- **Hora del endpoint:** en el momento del caso, el reloj de Windows iba unos **16 s adelantado** porque el servicio W32Time estaba detenido (detectado y corregido durante el Escenario 1). Las horas tomadas de los registros de Windows en este caso están desplazadas en esa magnitud. No afecta a la conclusión, porque la relación padre-hijo entre procesos no depende de la hora.
- **Configuración de Sysmon:** SwiftOnSecurity v74 usa el esquema 4.50, mientras que Sysmon 15.22 admite el 4.91. No influye en este caso.
- **Las rutas aparecen con doble barra invertida (`\\`)** en las salidas JSON del Manager por el escape de caracteres; en este documento se muestran normalizadas.

---

## 7. Lecciones aprendidas

- Una herramienta de seguridad también genera telemetría. Lo primero al desplegar un agente es **establecer una línea base** de lo que hace el propio agente, para no confundirlo después con actividad sospechosa.
- La descripción de una regla no basta para valorar una alerta. Para llegar a una conclusión fiable hay que examinar el **contexto**: proceso padre, usuario, directorio de trabajo y correlación temporal con otros registros.
- Antes de ajustar una regla hay que confirmar que el patrón se repite y diseñar la exclusión más estrecha posible.

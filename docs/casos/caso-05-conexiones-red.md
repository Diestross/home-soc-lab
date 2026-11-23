# Caso 5 — Conexiones de red: descargas con PowerShell y BITS

| Campo | Valor |
|---|---|
| **Fecha** | 2026-11-23 |
| **Endpoint** | `win10-host` (agente `001`) — Windows 11 Pro, compilación 26300 |
| **Fuentes de datos** | Sysmon 15.22 (eventos 1, 3 y 22) · Registro del Sistema de Windows (evento 7040) |
| **Técnicas MITRE ATT&CK** | T1071.001 — Web Protocols · T1105 — Ingress Tool Transfer · T1197 — BITS Jobs |
| **Tipo de caso** | Escenario planificado de la Fase 4 (escenario 5) + ingeniería de detección |
| **Resultado** | ⚠️ Ninguna conexión generaba alerta con la configuración por defecto → ✅ detección con las reglas 100130 y 100131 |

---

## 1. Objetivo

Comprobar si Wazuh detecta conexiones de red generadas deliberadamente desde el endpoint. La pregunta central en un SOC ante este tipo de actividad es: **¿qué proceso se conectó, a dónde y por qué puerto?**

Se probaron tres variantes:

| Prueba | Acción | Técnica |
|---|---|---|
| **A** | PowerShell descarga `https://example.com` | T1071.001, T1105 |
| **B** | PowerShell se conecta al puerto 22 de otro equipo de la red local (la VM de Wazuh) | Reconocimiento interno |
| **C** | `bitsadmin` descarga la misma página mediante el servicio BITS | T1197, T1105 |

> `example.com` es un dominio reservado para documentación y pruebas, y su página es texto plano.

---

## 2. Cobertura inicial

### 2.1 Qué registra Sysmon (configuración SwiftOnSecurity)

**Evento 3 (conexiones de red):** solo se registran si se cumple alguna de estas condiciones:

| Criterio | Ejemplos |
|---|---|
| El proceso es un LOLBin o una herramienta habitual en ataques | `powershell.exe`, `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wscript.exe`, `cmd.exe`, `msiexec.exe`, `notepad.exe`… |
| El ejecutable está en una ruta sospechosa | Empieza por `C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`, `C:\Recycle`, `C:\perflogs`… |

**Evento 22 (consultas DNS):** `<DnsQuery onmatch="exclude">`, es decir, se registran **todas** las consultas salvo una lista de dominios excluidos.

### 2.2 Reglas de Wazuh

**Evento 3** (`0810-sysmon_id_3.xml`):

| Regla | Nivel | Condición |
|---|---|---|
| 92101 | **0** | `powershell.exe` + TCP (agrupa, no alerta) |
| 92102 / 92103 | 6 | Hija de la 92101: puerto de destino **135** (RPC) o **389** (LDAP) |
| 92104 | 15 | El nombre del ejecutable contiene el carácter **U+202E** (*Right-to-Left Override*), usado para disfrazar extensiones |
| 92105 / 92106 | 3 | Cualquier proceso hacia los puertos 135/445 (SMB) |
| 92107 | 4 | `wscript.exe` o `cscript.exe` + TCP |

**Evento 22:** solo existe la regla **61650, de nivel 0**, sin reglas hijas. Las consultas DNS **nunca** generan alerta.

**`bitsadmin`:** no hay ninguna regla del evento 1 que lo mencione.

**Hipótesis:** ninguna de las tres pruebas debería generar alertas.

---

## 3. Prueba inicial (configuración por defecto)

```powershell
$inicio = Get-Date
Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing | Out-Null                                                   # A
Start-Sleep -Seconds 5
Test-NetConnection 192.168.0.5 -Port 22 | Select-Object RemotePort, TcpTestSucceeded                                       # B
Start-Sleep -Seconds 5
bitsadmin /transfer HomeSOCLab-E5 /download /priority foreground https://example.com/ C:\Users\Public\HomeSOCLab-E5.html   # C
Remove-Item C:\Users\Public\HomeSOCLab-E5.html
```

La descarga con `bitsadmin` se completó (577 bytes).

### 3.1 Telemetría en el endpoint

| Hora | Evento | Proceso | Detalle |
|---|---|---|---|
| 17:14:11 | 22 | `powershell.exe` | Consulta DNS `example.com` |
| 17:14:11 | 3 | `powershell.exe` | → `104.20.23.154:443` |
| 17:14:18 | 3 | `powershell.exe` | → `192.168.0.5:22` |
| 17:14:37 | 1 | `bitsadmin.exe` | `/transfer HomeSOCLab-E5 /download /priority foreground https://example.com/ C:\Users\Public\HomeSOCLab-E5.html` |
| 17:14:43 | 22 | **`svchost.exe`** | Consulta DNS `example.com` |
| — | 3 | — | **No hay ninguna conexión de `bitsadmin.exe` ni de `svchost.exe`** |

### 3.2 Alertas en Wazuh

```text
2026-11-23T17:14:39.110-0500   61104   3   Service startup type was changed   7040
```

Detalle del evento 7040:

```text
param1: Servicio de transferencia inteligente en segundo plano (BITS)
param2: inicio por solicitud
param3: inicio automático
```

**Resultado:** ninguna alerta de las conexiones. La única alerta es un efecto secundario de la prueba C.

---

## 4. Hallazgos

### 4.1 Ejecución delegada de BITS: la descarga no deja rastro de conexión

`bitsadmin.exe` no descarga nada por sí mismo: le encarga el trabajo al **servicio BITS**, que se ejecuta dentro de `svchost.exe`. Lo demuestra el evento 22: quien resolvió `example.com` fue `svchost.exe`, seis segundos después de lanzar `bitsadmin`.

Como `svchost.exe` no está en la lista de inclusión de Sysmon, **la conexión de la descarga no queda registrada**. Solo quedan tres huellas indirectas:

| Huella | Fuente | Alerta por defecto |
|---|---|---|
| `bitsadmin.exe /transfer … https://example.com/` | Sysmon 1 | ❌ Ninguna |
| `svchost.exe` resuelve `example.com` | Sysmon 22 | ❌ Regla 61650, nivel 0 |
| El servicio BITS pasa de "inicio por solicitud" a "inicio automático" | Sistema 7040 | ✅ 61104, **nivel 3**, con una descripción genérica que no menciona BITS |

Esta es la esencia de la ejecución delegada (*proxy execution*): la acción la realiza un proceso de confianza en lugar del que la pidió, y así se esquivan los controles centrados en el proceso.

### 4.2 Cómo relacionar una conexión con un dominio

Al revisar la telemetría, un primer filtro que buscaba `example` en los eventos 3 **descartó la conexión de la prueba A**. El evento 3 guarda la **IP** de destino (`104.20.23.154`), y el campo `DestinationHostname` contiene, en el mejor de los casos, el nombre inverso de la IP, no el dominio consultado.

Para responder "¿a qué dominio se conectó este proceso?" hay que **cruzar** dos eventos:

```text
Evento 22:  17:14:11  powershell.exe  consulta  example.com
Evento 3:   17:14:11  powershell.exe  conecta   104.20.23.154:443
            └── mismo proceso, mismo segundo → la conexión corresponde a example.com
```

### 4.3 Ruido de aplicaciones instaladas en el perfil del usuario

En el mismo intervalo, Sysmon registró 15 conexiones de un navegador instalado dentro de la carpeta del usuario (mDNS, puerto 5353, y una conexión HTTPS). Se registran por el criterio `Image begin with C:\Users` de la configuración. Ese criterio es útil para detectar malware descargado, pero también registra cualquier aplicación legítima instalada por el usuario en su perfil.

> ⚠️ **Privacidad:** esas conexiones revelan qué software usa la persona y el nombre del equipo. No deben publicarse sin sanitizar.

---

## 5. Reglas personalizadas

### 5.1 Diseño

| Regla | Cuelga de | Nivel | Se activa cuando… |
|---|---|---|---|
| **100130** | Grupo `sysmon_event1` | **10** | `bitsadmin.exe` se ejecuta con `/transfer`, `/addfile`, `/download` o `/SetNotifyCmdLine` |
| **100131** | 92101 | **6** | `powershell.exe` abre una conexión TCP hacia una **IP pública** |

**Justificación:**

- **100130:** `bitsadmin` está obsoleto, y su uso legítimo para descargar archivos es muy poco común. Como la conexión no es visible (§4.1), se detecta la **ejecución**, que sí lo es.
- **100131:** que PowerShell se conecte a Internet es sospechoso, pero los administradores también lo hacen, por ejemplo para descargar módulos. El nivel 6 indica "revisar en contexto". Se excluyen las IP privadas, de loopback y link-local para no alertar del tráfico de la red local.

### 5.2 Reglas

Archivo completo en [`configs/wazuh/local_rules.xml`](../../configs/wazuh/local_rules.xml).

```xml
<!-- Home SOC Lab - Caso 5: descargas con BITS y conexiones de PowerShell a Internet -->
<group name="local,sysmon,network,">
  <rule id="100130" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\bitsadmin\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s/(transfer|addfile|download|setnotifycmdline)\b</field>
    <description>bitsadmin used to create a BITS transfer job (possible file download): $(win.eventdata.commandLine)</description>
    <mitre>
      <id>T1197</id>
      <id>T1105</id>
    </mitre>
  </rule>

  <rule id="100131" level="6">
    <if_sid>92101</if_sid>
    <field name="win.eventdata.destinationIp" type="pcre2">^(?!(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|::1$|(?i:fe80:|f[cd][0-9a-f]{2}:)))</field>
    <description>PowerShell opened a TCP connection to a public IP address: $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
    <mitre>
      <id>T1071.001</id>
      <id>T1105</id>
    </mitre>
  </rule>
</group>
```

La expresión de la 100131 usa una **búsqueda anticipada negativa** `(?!…)`: coincide con cualquier IP que **no** empiece por un rango privado (10.x, 172.16–31.x, 192.168.x), de loopback (127.x, `::1`), link-local (169.254.x, `fe80:`) o privado de IPv6 (`fc`/`fd`).

Despliegue: copia de seguridad de `local_rules.xml`, `wazuh-analysisd -t` y reinicio del Manager solo tras `CONFIGURACION OK`.

---

## 6. Validación

Repetición de las tres pruebas a las 17:33:

```text
2026-11-23T17:33:23.334-0500  100131  6   PowerShell opened a TCP connection to a public IP address: 104.20.23.154:443  3
2026-11-23T17:33:43.098-0500  100130  10  bitsadmin used to create a BITS transfer job (possible file download): "C:\WINDOWS\system32\bitsadmin.exe" /transfer HomeSOCLab-E5 /download /priority foreground https://example.com/ C:\Users\Public\HomeSOCLab-E5.html  1
2026-11-23T17:33:43.198-0500  61104   3   Service startup type was changed  7040
```

| Prueba | Esperado | Observado |
|---|---|---|
| A: PowerShell → `example.com:443` | 100131 (6) | ✅ 100131 (6) |
| B: PowerShell → `192.168.0.5:22` | Ninguna (red interna excluida) | ✅ Ninguna |
| C: `bitsadmin /transfer` | 100130 (10) | ✅ 100130 (10) |
| C: cambio de inicio del servicio BITS | 61104 (3) | ✅ 61104 (3), 100 ms después de la 100130 |

![Alertas de validación de las reglas 100130 y 100131](../../evidencias/caso-05/01-alertas-validacion-100130-100131.png)

**Investigación:** ante una alerta 100130, el analista puede corroborar que hubo una descarga real buscando, en los segundos siguientes, la alerta 61104 (BITS cambia a inicio automático) y la consulta DNS de `svchost.exe` (evento 22) al dominio de la URL que aparece en la línea de comandos.

---

## 7. Limitaciones

1. **La conexión de BITS sigue sin verse.** La regla 100130 detecta `bitsadmin.exe`, pero no los trabajos BITS creados con los cmdlets de PowerShell (`Start-BitsTransfer`) ni mediante su API COM. Esas variantes no se han probado.
2. **Se excluye el tráfico interno.** La regla 100131 no alerta de conexiones de PowerShell a la red local, así que el **reconocimiento interno y el movimiento lateral** (prueba B) siguen sin detectarse, salvo en los puertos 135/389/445 que cubren las reglas de serie.
3. **Solo cubre PowerShell.** Otros LOLBins que Sysmon registra (`certutil`, `mshta`, `rundll32`, `regsvr32`…) siguen en nivel 0 o sin regla cuando se conectan a Internet. `certutil` no se probó, porque Microsoft Defender suele bloquear las descargas con `certutil -urlcache`.
4. **El DNS no genera alertas.** No hay reglas para el evento 22. Detectar dominios maliciosos requeriría integrar listas de reputación o reglas de dominios recientes o poco comunes.
5. **Posibles falsos positivos de la 100131.** Scripts de administración, actualizaciones de módulos y herramientas que usan PowerShell legítimamente generarán alertas de nivel 6. En un entorno real habría que establecer una línea base de destinos habituales.
6. **Visibilidad limitada a los procesos de la lista de Sysmon.** Las conexiones de procesos que no están en la lista de inclusión, como `svchost.exe` o los programas de `Program Files`, no se registran.
7. **Solo IPv4 en la práctica.** Los rangos IPv6 de la exclusión se han escrito pero no se han probado.

---

## 8. Lecciones aprendidas

- **Detectar la intención cuando no se puede ver la acción.** La conexión de BITS no deja rastro en Sysmon, pero la orden que la provoca (`bitsadmin /transfer`) sí. Si una fuente no ve algo, hay que buscar otra huella de la misma actividad.
- **La ejecución delegada rompe la relación "proceso = actor".** El proceso que se conecta (`svchost.exe`) no es el que lo pidió (`bitsadmin.exe`). Investigar requiere cruzar eventos por tiempo y contexto.
- **Un evento de sistema "aburrido" puede ser una pista.** El cambio de tipo de inicio de BITS (7040) es la única huella automática de la descarga en el conjunto de reglas por defecto.
- **Cuidado con los filtros al investigar.** Un filtro mal planteado (buscar el dominio en el evento 3) llegó a ocultar un evento que sí existía. Antes de concluir que algo "no se registró", hay que comprobar el filtro.
- **Los criterios amplios de Sysmon tienen coste.** Registrar todo lo que se ejecuta desde `C:\Users` aporta detecciones valiosas, pero también ruido y datos personales de las aplicaciones legítimas del usuario.

---

## 9. Filas para la matriz de pruebas

| ID | Escenario | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E5-A0 | PowerShell → Internet (reglas por defecto) | T1071.001, T1105 | Sysmon 3, 22 | Alguna alerta | Ninguna (92101 y 61650 de nivel 0) | ❌ Brecha |
| E5-B0 | PowerShell → red interna:22 (reglas por defecto) | Reconocimiento | Sysmon 3 | Alguna alerta | Ninguna (92101 de nivel 0) | ❌ Brecha (se mantiene) |
| E5-C0 | `bitsadmin /transfer` (reglas por defecto) | T1197, T1105 | Sysmon 1, 22 · Sistema 7040 | Alguna alerta | Solo 61104 (3), indirecta | ⚠️ Cobertura mínima |
| E5-A1 | PowerShell → Internet (con la 100131) | T1071.001, T1105 | Sysmon 3 | 100131 (6) | 100131 (6) | ✅ Superado |
| E5-B1 | PowerShell → red interna:22 (con la 100131) | Reconocimiento | Sysmon 3 | Ninguna (exclusión) | Ninguna | ✅ Conforme al diseño |
| E5-C1 | `bitsadmin /transfer` (con la 100130) | T1197, T1105 | Sysmon 1 | 100130 (10) | 100130 (10) + 61104 (3) | ✅ Superado |

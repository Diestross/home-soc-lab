# Caso 4 — Persistencia mediante claves Run del registro: Sysmon frente al FIM de Wazuh

| Campo | Valor |
|---|---|
| **Fecha** | 2026-11-17 |
| **Endpoint** | `win10-host` (agente `001`) — Windows 11 Pro, compilación 26300 |
| **Fuentes de datos** | Sysmon 15.22 (evento 13, valor del registro establecido) · FIM de registro del agente de Wazuh (`syscheck`) |
| **Técnica MITRE ATT&CK** | T1547.001 — Registry Run Keys / Startup Folder |
| **Tipo de caso** | Escenario planificado de la Fase 4 (escenario 4) + ingeniería de detección + comparación de fuentes |
| **Resultado** | ⚠️ Sin alertas con la configuración por defecto → ✅ detección en tiempo real con las reglas 100120 y 100121 · FIM: detección retardada y solo de HKLM |

---

## 1. Objetivo

Comprobar si Wazuh detecta que se añade un valor a las claves `Run` del registro, que Windows ejecuta automáticamente en cada inicio de sesión. Se comparan dos fuentes que pueden ver el mismo cambio:

| Fuente | Funcionamiento |
|---|---|
| **Sysmon** (evento 13) | Registra cada cambio en el momento en que ocurre |
| **FIM de registro** del agente de Wazuh | Compara el registro con una foto anterior en cada escaneo programado (por defecto, cada 43 200 s = 12 h) |

Se prueban las dos variantes de la clave:

| Clave | ¿Requiere privilegios? |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | **No**. Es la variante preferida por el malware |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Sí (administrador) |

---

## 2. Cobertura inicial

**Sysmon (configuración SwiftOnSecurity):** vigila toda clave cuya ruta contenga `CurrentVersion\Run`, en HKCU y HKLM.

```xml
<TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
```

**FIM del agente (`ossec.conf`):** vigila `Run`, `RunOnce` y `RunOnceEx` **solo en `HKEY_LOCAL_MACHINE`**. No incluye ninguna clave de `HKEY_CURRENT_USER`.

```xml
<frequency>43200</frequency>
<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
<windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</windows_registry>
```

**Reglas de Wazuh para el evento 13** (`0860-sysmon_id_13.xml`):

```text
92300  nivel 0   "Added registry content to be executed on next logon"   ← agrupa, no alerta
 ├── 92301  nivel 12  …si el valor contiene .lnk, .vbs o .vba
 ├── 92302  nivel 6   …si lo escribe reg.exe
 ├── 92303  nivel 12  …si apunta a VNC o tvnserver.exe
 └── …
```

---

## 3. Prueba 1 — Configuración por defecto (Sysmon)

```powershell
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'HomeSOCLab-E4-HKCU' -Value 'C:\Windows\System32\notepad.exe' -PropertyType String -Force
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'HomeSOCLab-E4-HKLM' -Value 'C:\Windows\System32\notepad.exe' -PropertyType String -Force
```

### 3.1 Telemetría en el endpoint

| Hora | Proceso | Clave | Valor |
|---|---|---|---|
| 15:36:21 | `powershell.exe` | `HKU\[SID]\Software\Microsoft\Windows\CurrentVersion\Run\HomeSOCLab-E4-HKCU` | `C:\Windows\System32\notepad.exe` |
| 15:36:26 | `powershell.exe` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\HomeSOCLab-E4-HKLM` | `C:\Windows\System32\notepad.exe` |
| 15:36:31 | `sihost.exe` | `HKU\[SID]\...\CurrentVersion\RunNotification\StartupTNotiHomeSOCLab-E4-HKCU` | `DWORD (0x00000001)` |
| 15:36:41 | `sihost.exe` | `HKU\[SID]\...\CurrentVersion\RunNotification\StartupTNotiHomeSOCLab-E4-HKLM` | `DWORD (0x00000000)` |

> Sysmon escribe las rutas de HKCU como `HKU\<SID del usuario>\...`. El SID identifica la cuenta y debe sanitizarse en las evidencias.

### 3.2 Alertas en Wazuh

**Ninguna.** La regla 92300 reconoce los eventos, pero tiene **nivel 0**, y ninguna de sus reglas hijas coincidió: el valor era un `.exe`, lo escribió PowerShell (no `reg.exe`) y no apuntaba a una herramienta de acceso remoto.

**Brecha:** PowerShell escribiendo en una clave `Run` cualquier ejecutable, por ejemplo `C:\Users\Public\malware.exe`, **no genera ninguna alerta** con el conjunto de reglas por defecto.

### 3.3 Hallazgo: eventos de `RunNotification`

`sihost.exe` escribió en `CurrentVersion\RunNotification` unos segundos después de cada cambio. Es la función de Windows 11 que **notifica al usuario cuando se añade un programa al inicio**. Es actividad benigna, pero la expresión regular de la regla 92300 también la recoge, porque `RUN` no exige un límite de palabra detrás. Una regla nueva basada en la 92300 debe excluirla para no generar alertas duplicadas.

---

## 4. Reglas personalizadas

### 4.1 Diseño

| Regla | Cuelga de | Nivel | Se activa cuando… |
|---|---|---|---|
| **100120** | 92300 | **7** | Se escribe un valor **directamente** en `Run`, `RunOnce`, `RunOnceEx`, `RunServices` o `RunServicesOnce`. Excluye `RunNotification` |
| **100121** | 100120 | **12** | Además, el valor apunta a un **LOLBin** o a una **ruta escribible por usuarios** |

Cualquier valor nuevo en una clave de inicio automático merece revisión (nivel 7). Si además apunta a un intérprete o a una carpeta escribible por cualquier usuario, el patrón coincide con el de una persistencia maliciosa típica (nivel 12).

### 4.2 Reglas

Archivo completo en [`configs/wazuh/local_rules.xml`](../../configs/wazuh/local_rules.xml).

```xml
<!-- Home SOC Lab - Caso 4: valores añadidos a claves Run (persistencia) -->
<group name="local,sysmon,autostart,">
  <rule id="100120" level="7">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)\\+CurrentVersion\\+Run(?:Once|OnceEx|Services|ServicesOnce)?\\+[^\\]+$</field>
    <description>Value set in a Run registry key (autostart on logon): $(win.eventdata.targetObject)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="100121" level="12">
    <if_sid>100120</if_sid>
    <field name="win.eventdata.details" type="pcre2">(?i)(?:\\+(?:Users\\+Public|AppData|Temp|ProgramData)\\+|(?:^|\\+|\s|")(?:powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript)(?:\.exe)?(?:\s|"|$))</field>
    <description>Run registry key points to a LOLBin or user-writable path: $(win.eventdata.details)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>
</group>
```

| Expresión | Explicación |
|---|---|
| `\\+CurrentVersion\\+Run(?:Once\|…)?\\+[^\\]+$` | La ruta termina en `\Run` (o una variante) seguida de **un solo nivel más**, el nombre del valor. `\RunNotification\...` no coincide, porque tras `Run` viene `Notification` y no una barra. `\\+` acepta barras simples o dobles, porque Wazuh guarda las barras escapadas |
| `\\+(?:Users\\+Public\|AppData\|Temp\|ProgramData)\\+` | El valor contiene una ruta escribible por usuarios |
| `(?:^\|\\+\|\s\|")(?:powershell\|…\|cscript)(?:\.exe)?(?:\s\|"\|$)` | El valor ejecuta un LOLBin, delimitado por el inicio del texto, una barra, un espacio o comillas. Evita coincidencias parciales como `cmdkey.exe` |

Despliegue: copia de seguridad de `local_rules.xml`, `wazuh-analysisd -t` y reinicio del Manager solo tras `CONFIGURACION OK`.

### 4.3 Validación

```powershell
$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $run -Name 'HomeSOCLab-E4-benigno' -Value 'C:\Windows\System32\notepad.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $run -Name 'HomeSOCLab-E4-lolbin' -Value 'powershell.exe -NoProfile -WindowStyle Hidden -Command exit' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $run -Name 'HomeSOCLab-E4-ruta' -Value 'C:\Users\Public\HomeSOCLab-test.exe' -PropertyType String -Force | Out-Null
'benigno','lolbin','ruta' | ForEach-Object { Remove-ItemProperty -Path $run -Name "HomeSOCLab-E4-$_" }
```

```text
2026-11-17T15:55:08.606-0500  100120  7   HKU\[SID]\...\CurrentVersion\Run\HomeSOCLab-E4-benigno  C:\Windows\System32\notepad.exe
2026-11-17T15:55:13.654-0500  100121  12  HKU\[SID]\...\CurrentVersion\Run\HomeSOCLab-E4-lolbin   powershell.exe -NoProfile -WindowStyle Hidden -Command exit
2026-11-17T15:55:18.021-0500  100121  12  HKU\[SID]\...\CurrentVersion\Run\HomeSOCLab-E4-ruta     C:\Users\Public\HomeSOCLab-test.exe
```

| Valor | Esperado | Observado |
|---|---|---|
| `benigno` (notepad) | 100120 (7) | ✅ 100120 (7) |
| `lolbin` (PowerShell oculto) | 100121 (12) | ✅ 100121 (12) |
| `ruta` (`C:\Users\Public\`) | 100121 (12) | ✅ 100121 (12) |
| Eventos `RunNotification` de `sihost.exe` | Ninguna alerta | ✅ Ninguna alerta |

---

## 5. Prueba 2 — FIM de registro del agente

### 5.1 Primer intento: forzar el escaneo reiniciando el agente

Se reinició el agente dos veces (16:04 y 16:10) para forzar un escaneo, con el valor de HKLM presente la primera vez y ya borrado la segunda. **No se generó ninguna alerta.**

El log del agente mostraba escaneos completos en ambos reinicios (unos 35 s cada uno):

```text
16:04:45 (6008): File integrity monitoring scan started.
16:05:20 (6009): File integrity monitoring scan ended.
16:10:27 (6008): File integrity monitoring scan started.
16:11:00 (6009): File integrity monitoring scan ended.
```

Además, no había **ninguna** alerta del FIM para este agente desde su instalación (9 de noviembre).

**Hipótesis:** el primer escaneo tras arrancar el agente solo crea una **línea base**, sin comparar con nada. Reiniciar el agente no sirve para forzar una detección.

### 5.2 Prueba controlada: escaneo cada 5 minutos

Se redujo temporalmente la frecuencia del FIM en `ossec.conf` del agente, dentro del bloque `<syscheck>`, previa copia de seguridad:

```xml
<frequency>300</frequency>   <!-- antes: 43200 -->
```

Secuencia: reinicio del agente (escaneo de línea base, 16:19:16–16:19:49) → valores creados **sin reiniciar** (16:20:34) → siguiente escaneo programado (16:24:52–16:25:18).

```text
2026-11-17T16:25:17.290-0500  594  5  Registry Key Integrity Checksum Changed  HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
2026-11-17T16:25:17.332-0500  752  5  Registry Value Entry Added to the System  HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  HomeSOCLab-E4-FIM-HKLM
```

Borrado de los valores sin reiniciar (16:29:31) → siguiente escaneo (16:30:19–16:30:44):

```text
2026-11-17T16:30:44.938-0500  751  5  Registry Value Entry Deleted.  HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  HomeSOCLab-E4-FIM-HKLM
```

**Hipótesis confirmada:** el FIM solo detecta cambios entre **dos escaneos consecutivos sin reinicio por medio**.

Tras la prueba se restauró la configuración original desde la copia de seguridad y se verificó en el log del agente: `File integrity monitoring scan frequency: 43200 seconds`.

### 5.3 Ruido observado en el FIM

En el mismo escaneo aparecieron cambios legítimos en otras claves vigiladas:

| Clave | Qué es |
|---|---|
| `HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\[SID]` | *Background Activity Moderator*: registra qué aplicaciones ha usado cada usuario |
| `HKLM\System\CurrentControlSet\Services\W32Time\SecureTimeLimits` | Datos internos del servicio de hora |

> ⚠️ **Privacidad:** las alertas de la clave `bam` muestran el SID, el nombre de usuario y las rutas de las aplicaciones que usa la persona. No deben publicarse sin sanitizar.

---

## 6. Comparación de fuentes

| Criterio | Sysmon + reglas 100120/100121 | FIM de registro de Wazuh |
|---|---|---|
| Valor en **HKLM** `Run` | ✅ < 1 s | ✅ Al siguiente escaneo (**hasta 12 h** por defecto; 4 min 43 s con frecuencia de 5 min) |
| Valor en **HKCU** `Run` (sin privilegios) | ✅ < 1 s | ❌ Fuera de su alcance |
| Borrado del valor | ❌ No cubierto (evento 12 de Sysmon sin regla) | ✅ Regla 751 al siguiente escaneo |
| Muestra el **proceso** que hizo el cambio | ✅ (`image`) | ❌ |
| Muestra el **contenido** del valor | ✅ (`details`) | Solo el nombre del valor |
| Detecta cambios hechos con el agente detenido | ❌ | ✅ Si hay dos escaneos consecutivos sin reinicio entre medias |
| Depende de un escaneo previo sin reinicio | No | **Sí** |

**Conclusión:** las dos fuentes se complementan. Sysmon da detección inmediata y contexto (quién y qué); el FIM aporta una verificación independiente del estado del registro y detecta los borrados. Sin embargo, **el FIM por sí solo no basta** para detectar a tiempo la persistencia en claves `Run`, y no cubre en absoluto la variante sin privilegios (HKCU).

---

## 7. Limitaciones

1. **El borrado de valores no se detecta por Sysmon.** Las reglas 100120 y 100121 solo tratan el evento 13. El borrado genera un evento 12, que no tiene regla.
2. **Solo se ha probado la mitad de T1547.001.** La carpeta de inicio (`shell:startup`) y otros puntos de autoarranque (`Winlogon`, servicios, *Image File Execution Options*, `Active Setup`) no se han probado.
3. **Lista de LOLBins incompleta**, igual que en el Caso 3.
4. **Posibles falsos positivos de la 100120**, porque los instaladores legítimos también escriben en `Run`. Su nivel 7 refleja que pide revisión, no que sea maliciosa.
5. **El FIM no vigila HKCU.** Wazuh permite añadir claves de registro, pero vigilar los perfiles de usuario requiere configuración adicional que no se ha evaluado.
6. **El comportamiento de línea base del FIM** implica que los cambios hechos mientras el agente está detenido, o entre un reinicio y el primer escaneo, pueden pasar desapercibidos para el FIM.
7. **El contexto de privilegios de la prueba de validación** no se verificó en el endpoint. Para la variante HKCU no cambia el resultado, porque las reglas no comprueban el usuario ni el nivel de integridad.

---

## 8. Lecciones aprendidas

- **Una regla de nivel 0 no es una detección.** La 92300 "reconoce" exactamente nuestro caso, pero sin una regla hija que coincida no se genera ninguna alerta. Al evaluar la cobertura hay que mirar el nivel efectivo, no solo si existe una regla.
- **Seguir el evento a lo largo de toda la cadena** (endpoint → regla base → reglas hijas → alerta) permite localizar en qué punto se pierde la detección.
- **El sistema operativo también escribe en zonas "sensibles".** `sihost.exe` y `RunNotification` muestran que una regla demasiado amplia genera ruido. Las exclusiones deben ser precisas.
- **Entender cómo funciona una fuente antes de probarla.** Reiniciar el agente parecía una forma razonable de forzar el escaneo del FIM, pero solo crea una nueva línea base. La prueba correcta requería dos escaneos consecutivos.
- **Los cambios temporales se documentan y se revierten.** La frecuencia del FIM se cambió con copia de seguridad previa, y se verificó en el log que volvía a su valor original.
- **Las fuentes de telemetría pueden exponer datos personales.** Las rutas de `HKU\[SID]` y la clave `bam` revelan la identidad y los hábitos de uso del usuario.

---

## 9. Filas para la matriz de pruebas

| ID | Escenario | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E4-A | Valor `notepad.exe` en HKCU/HKLM `Run` (reglas por defecto) | T1547.001 | Sysmon 13 | Alguna alerta | Ninguna (92300 de nivel 0) | ❌ Brecha |
| E4-B1 | Valor benigno en HKCU `Run` | T1547.001 | Sysmon 13 | 100120 (7) | 100120 (7) | ✅ Superado |
| E4-B2 | Valor con LOLBin oculto en HKCU `Run` | T1547.001 | Sysmon 13 | 100121 (12) | 100121 (12) | ✅ Superado |
| E4-B3 | Valor con ruta `\Users\Public\` en HKCU `Run` | T1547.001 | Sysmon 13 | 100121 (12) | 100121 (12) | ✅ Superado |
| E4-B4 | Eventos `RunNotification` de `sihost.exe` | — | Sysmon 13 | Ninguna alerta | Ninguna alerta | ✅ Superado |
| E4-C1 | FIM tras reiniciar el agente | T1547.001 | FIM | 752 | Ninguna (línea base) | ⚠️ Comportamiento documentado |
| E4-C2 | Valor en HKLM `Run` con escaneos cada 5 min | T1547.001 | FIM | 752 (5) | 752 (5), 4 min 43 s después | ✅ Superado |
| E4-C3 | Valor en HKCU `Run` con escaneos cada 5 min | T1547.001 | FIM | Ninguna (fuera de alcance) | Ninguna | ✅ Conforme a lo esperado |
| E4-C4 | Borrado del valor en HKLM `Run` | T1547.001 | FIM | 751 (5) | 751 (5), 1 min 13 s después | ✅ Superado |

# Caso 3 — Creación de tareas programadas: brecha de visibilidad y reglas personalizadas

| Campo | Valor |
|---|---|
| **Fecha** | 2026-11-17 |
| **Endpoint** | `win10-host` (agente `001`) — Windows 11 Pro, compilación 26300 |
| **Fuentes de datos** | Sysmon 15.22 (eventos 1 y 11) · Registro de Seguridad de Windows (eventos 4698 y 4699) |
| **Técnicas MITRE ATT&CK** | T1053.005 — Scheduled Task · T1070 — Indicator Removal |
| **Tipo de caso** | Escenario planificado de la Fase 4 (escenario 3) + ingeniería de detección |
| **Resultado** | ⚠️ Sin detección real con la configuración por defecto → ✅ visibilidad y detección tras activar la auditoría y crear las reglas 100110 y 100111 |

---

## 1. Objetivo

Comprobar si Wazuh detecta la creación de una tarea programada, una de las formas más habituales de conseguir **persistencia** en Windows (ejecutar código tras un reinicio o a una hora concreta), y si distingue las tareas legítimas de las sospechosas.

---

## 2. Fuentes de datos y reglas disponibles

| Fuente | Evento | Estado inicial |
|---|---|---|
| Sysmon | 1: ejecución de `schtasks.exe` | ✅ Incluido en la configuración de SwiftOnSecurity (`<Image condition="image">schtasks.exe</Image>`) |
| Sysmon | 11: archivo de la tarea en `C:\Windows\System32\Tasks\` | ✅ Incluido y etiquetado como `T1053` |
| Seguridad | 4698: tarea creada · 4699: tarea eliminada | ❌ La subcategoría "Otros eventos de acceso a objetos" estaba en **Sin auditoría** |

Reglas del conjunto por defecto relacionadas:

```bash
sudo grep -rn -i -E '<description>.*(schtasks|scheduled task)' /var/ossec/ruleset/rules/
```

```xml
<rule id="60228" level="4">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4698$</field>
  <description>A scheduled task was created</description>
  <mitre><id>T1053</id></mitre>
</rule>
```

- La regla **60228** depende del evento 4698, que **no se generaba**.
- **No hay ninguna regla para el evento 4699** (borrado de tareas).
- **No hay ninguna regla específica** para `schtasks.exe` en las reglas de Sysmon.

> La subcategoría de auditoría se consultó por su GUID, porque los nombres están traducidos en un Windows en español:
> `auditpol /get /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}"`

---

## 3. Fase A — Configuración por defecto

```powershell
$inicio = Get-Date
schtasks /create /tn "HomeSOCLab-E3" /tr "C:\Windows\System32\cmd.exe /c exit" /sc once /st 23:59 /f
```

### 3.1 Telemetría en el endpoint (Sysmon)

| Hora | Evento | Proceso | Detalle |
|---|---|---|---|
| 11:48:00 | 1 | `schtasks.exe` | `/create /tn HomeSOCLab-E3 /tr "C:\Windows\System32\cmd.exe /c exit" /sc once /st 23:59 /f` |
| 11:48:01 | 11 | **`svchost.exe`** | `C:\Windows\System32\Tasks\HomeSOCLab-E3` |

> El archivo de la tarea no lo escribe `schtasks.exe`, sino `svchost.exe`, que aloja el servicio Programador de tareas. En una investigación, el proceso que deja la huella en disco no siempre es el que inició la acción.

### 3.2 Alertas en Wazuh

```text
2026-11-17T11:48:01.627-0500   92004   4   Powershell process spawned Windows command shell instance
```

**Una sola alerta, y su descripción no corresponde a lo ocurrido.** No se lanzó ninguna consola `cmd.exe`: el proceso creado fue `schtasks.exe`. La lógica de la regla lo explica:

```xml
<rule id="92004" level="4">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">\\cmd\.exe</field>    <!-- busca en la LÍNEA DE COMANDOS -->
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\powershell\.exe</field>
  <description>Powershell process spawned Windows command shell instance</description>
</rule>
```

Datos del evento que la activó:

```text
image        C:\Windows\System32\schtasks.exe
commandLine  "C:\WINDOWS\system32\schtasks.exe" /create /tn HomeSOCLab-E3 /tr "C:\Windows\System32\cmd.exe /c exit" /sc once /st 23:59 /f
```

La regla 92004 se activó **por casualidad**, porque el argumento `/tr` contenía `\cmd.exe`. Además, su patrón **distingue mayúsculas y minúsculas** (no lleva `(?i)`).

**Conclusión de la fase A:** con la configuración por defecto **no hay ninguna detección real de la creación de tareas programadas**. Con una acción que no mencionara `cmd.exe`, no habría saltado ninguna alerta, aunque Sysmon tenía toda la información en el endpoint.

---

## 4. Fase B — Con auditoría de "Otros eventos de acceso a objetos"

### 4.1 Ajuste aplicado al endpoint

```powershell
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable
```

| Ajuste | Antes | Después | Cómo revertirlo |
|---|---|---|---|
| Auditoría "Otros eventos de acceso a objetos" | Sin auditoría | Aciertos | `auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:disable` |

### 4.2 Prueba

Dos tareas: una cuya acción contiene `cmd.exe` y otra que no.

```powershell
schtasks /create /tn "HomeSOCLab-E3-cmd" /tr "C:\Windows\System32\cmd.exe /c exit" /sc once /st 23:59 /f
schtasks /create /tn "HomeSOCLab-E3-notepad" /tr "C:\Windows\System32\notepad.exe" /sc once /st 23:59 /f
schtasks /delete /tn "HomeSOCLab-E3-cmd" /f
schtasks /delete /tn "HomeSOCLab-E3-notepad" /f
```

| Tarea | Fase A (sin auditoría) | Fase B (con auditoría) |
|---|---|---|
| `-cmd` | 92004 (4, descripción incorrecta) | 92004 (4) + **60228 (4)** |
| `-notepad` | — | **60228 (4)** |
| Borrado (4699) | — | **Ninguna alerta** |

**Conclusiones de la fase B:**

- Con el evento 4698, la creación de tareas se detecta **siempre**, sea cual sea su acción. Se confirma que la 92004 solo aparece cuando el comando menciona `cmd.exe`.
- La detección es de **nivel 4** (informativa) y **no distingue** una tarea de un actualizador legítimo de una que ejecuta un intérprete desde una carpeta pública.
- El **borrado de tareas no genera alerta**. Borrar la tarea después de usarla es una forma de eliminar rastros.

---

## 5. Reglas personalizadas

### 5.1 Análisis del campo `taskContent`

El evento 4698 incluye la **definición XML completa de la tarea** en el campo `win.eventdata.taskContent`:

```bash
sudo jq -r 'select(.rule.id=="60228" and .timestamp >= "2026-11-17T11:57:00") | .data.win.eventdata.taskContent' \
  /var/ossec/logs/alerts/alerts.json
```

Extracto (sanitizado):

```text
&lt;Actions Context=\"Author\"&gt;
  &lt;Exec&gt;
    &lt;Command&gt;C:\\Windows\\System32\\cmd.exe&lt;/Command&gt;
    &lt;Arguments&gt;/c exit&lt;/Arguments&gt;
  &lt;/Exec&gt;
&lt;/Actions&gt;
&lt;Principals&gt;
  &lt;Principal id=\"Author\"&gt;
    &lt;UserId&gt;[EQUIPO]\\[USUARIO]&lt;/UserId&gt;
```

**El XML llega escapado:** `<` y `>` aparecen como `&lt;` y `&gt;`, y las barras invertidas aparecen dobles. Una expresión regular que buscara `<Command>` literalmente nunca coincidiría.

> **Privacidad:** `taskContent` incluye el nombre del equipo y del usuario en `<Author>` y `<UserId>`. Hay que sanitizarlos en cualquier evidencia publicada.

### 5.2 Diseño

| Regla | Cuelga de | Nivel | Se activa cuando… |
|---|---|---|---|
| **100110** | 60228 (evento 4698) | **10** | La acción es un intérprete o LOLBin (`powershell`, `pwsh`, `cmd`, `mshta`, `rundll32`, `regsvr32`, `wscript`, `cscript`), con o sin ruta, **o** se ejecuta desde una ruta escribible por usuarios (`\Users\Public\`, `\AppData\`, `\Temp\`, `\ProgramData\`) |
| **100111** | 60103 (evento de auditoría correcto) | 5 | Se elimina una tarea programada (evento 4699) |

**Por qué no se sube de nivel la 60228 para todas las tareas:** muchos programas legítimos (actualizadores, antivirus, herramientas de copia de seguridad) crean tareas constantemente. Elevar solo las tareas con una acción sospechosa mantiene el ruido bajo y concentra la atención del analista donde importa.

### 5.3 Reglas

Archivo completo en [`configs/wazuh/local_rules.xml`](../../configs/wazuh/local_rules.xml).

```xml
<!-- Home SOC Lab - Caso 3: tareas programadas sospechosas y borrado de tareas -->
<group name="local,windows,scheduled_task,">
  <rule id="100110" level="10">
    <if_sid>60228</if_sid>
    <field name="win.eventdata.taskContent" type="pcre2">(?i)Command(?:\x26gt;|\x3e)(?:[^\x26\x3c]*\\+(?:Users\\+Public|AppData|Temp|ProgramData)\\+|(?:[^\x26\x3c]*\\+)?(?:powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript)(?:\.exe)?(?:\x26lt;|\x3c))</field>
    <description>Scheduled task created with a suspicious action (LOLBin or user-writable path): $(win.eventdata.taskName)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

  <rule id="100111" level="5">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4699$</field>
    <description>A scheduled task was deleted: $(win.eventdata.taskName)</description>
    <mitre>
      <id>T1070</id>
    </mitre>
  </rule>
</group>
```

**Cómo funciona la expresión regular de la 100110:**

| Fragmento | Significado |
|---|---|
| `Command(?:\x26gt;\|\x3e)` | La etiqueta `<Command>`, escapada (`&gt;`) o no (`>`) |
| `[^\x26\x3c]*` | Cualquier texto que no salga de la etiqueta (sin `&` ni `<`) |
| `\\+(?:Users\\+Public\|AppData\|Temp\|ProgramData)\\+` | **Alternativa 1:** una ruta escribible por usuarios, con barras simples o dobles |
| `(?:[^\x26\x3c]*\\+)?(?:powershell\|…\|cscript)(?:\.exe)?(?:\x26lt;\|\x3c)` | **Alternativa 2:** la acción **es** un intérprete o LOLBin, con o sin ruta y con o sin `.exe`, justo antes de cerrar la etiqueta. Exigir el cierre evita falsos positivos con nombres como `cmdkey.exe` |

### 5.4 Incidente durante el despliegue

La primera versión de la regla escribía `<`, `>` y `&lt;` literalmente dentro de la expresión regular. La validación falló:

```text
wazuh-analysisd: ERROR: (1226): Error reading XML file 'etc/rules/local_rules.xml': XMLERR: Element '))</field' not closed. (line 43).
wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
```

**Causa:** el archivo de reglas es XML, y un `<` literal en el texto de una regla se interpreta como el inicio de una etiqueta. Además, la clase `[^&lt;]` no significa "todo menos `&lt;`", sino "todo carácter excepto `&`, `l`, `t` y `;`", lo que habría excluido esas letras de las rutas.

**Solución:** escribir esos caracteres por su código hexadecimal, que PCRE2 entiende y que no afecta al XML: `\x3c` (`<`), `\x3e` (`>`), `\x26` (`&`).

**Recuperación:** como la validación se hizo **antes** de reiniciar, el Manager siguió funcionando con la configuración anterior. Se restauró la copia de seguridad, se volvió a validar y se añadió la versión corregida:

```bash
sudo bash -c 'cp "$(ls -t /var/ossec/etc/rules/local_rules.xml.bak-* | head -1)" /var/ossec/etc/rules/local_rules.xml'
sudo /var/ossec/bin/wazuh-analysisd -t && echo "CONFIGURACION OK"
# (añadir la versión corregida y validar de nuevo)
sudo systemctl restart wazuh-manager
```

> Si el Manager se hubiera reiniciado con el archivo roto, **no habría arrancado** y se habrían perdido eventos hasta corregirlo.

---

## 6. Fase C — Validación de las reglas

```powershell
$inicio = Get-Date
schtasks /create /tn "HomeSOCLab-E3-benigna" /tr "C:\Windows\System32\notepad.exe" /sc once /st 23:59 /f
Start-Sleep -Seconds 5
schtasks /create /tn "HomeSOCLab-E3-lolbin" /tr "powershell.exe -NoProfile -Command exit" /sc once /st 23:59 /f
Start-Sleep -Seconds 5
schtasks /create /tn "HomeSOCLab-E3-ruta" /tr "C:\Users\Public\HomeSOCLab-test.exe" /sc once /st 23:59 /f
Start-Sleep -Seconds 5
"benigna","lolbin","ruta" | ForEach-Object { schtasks /delete /tn "HomeSOCLab-E3-$_" /f }
```

> El archivo `C:\Users\Public\HomeSOCLab-test.exe` no existe. Las tareas se eliminan antes de su hora de ejecución, así que ninguna llega a ejecutarse.

```text
2026-11-17T12:29:56.901-0500  60228   4   A scheduled task was created                                               4698
2026-11-17T12:30:01.998-0500  100110  10  Scheduled task created with a suspicious action (...): \HomeSOCLab-E3-lolbin  4698
2026-11-17T12:30:07.708-0500  100110  10  Scheduled task created with a suspicious action (...): \HomeSOCLab-E3-ruta    4698
2026-11-17T12:30:12.765-0500  100111  5   A scheduled task was deleted: \HomeSOCLab-E3-benigna                        4699
2026-11-17T12:30:12.770-0500  100111  5   A scheduled task was deleted: \HomeSOCLab-E3-lolbin                         4699
2026-11-17T12:30:12.772-0500  100111  5   A scheduled task was deleted: \HomeSOCLab-E3-ruta                           4699
```

| Tarea | Creación (esperado → observado) | Borrado (esperado → observado) |
|---|---|---|
| `benigna` (notepad) | 60228 (4) → ✅ 60228 (4) | 100111 (5) → ✅ 100111 (5) |
| `lolbin` (powershell) | 100110 (10) → ✅ 100110 (10) | 100111 (5) → ✅ 100111 (5) |
| `ruta` (`\Users\Public\`) | 100110 (10) → ✅ 100110 (10) | 100111 (5) → ✅ 100111 (5) |

---

## 7. Limitaciones

1. **La detección depende de la política de auditoría.** Si se desactiva "Otros eventos de acceso a objetos", desaparecen la 60228, la 100110 y la 100111. Sysmon seguiría registrando `schtasks.exe` y el archivo de la tarea, pero **no hay ninguna regla que los trate**. Una regla basada en Sysmon daría una segunda capa de detección.
2. **Lista de LOLBins incompleta.** No incluye, por ejemplo, `certutil`, `bitsadmin`, `msiexec`, `forfiles` ni `msbuild`.
3. **Rutas entre comillas o con variables.** Una acción como `"%APPDATA%\x.exe"` o con comillas escapadas (`&quot;`) podría no coincidir con el patrón. No se ha probado.
4. **Solo se probó `schtasks.exe`.** Las tareas creadas con `Register-ScheduledTask` (PowerShell) o por COM también generan el 4698, pero no se ha verificado.
5. **No se cubre la modificación de tareas** (evento 4702). Un atacante podría modificar una tarea legítima existente en lugar de crear una nueva.
6. **Posibles falsos positivos.** Algunos programas legítimos crean tareas que ejecutan PowerShell o binarios desde `ProgramData`. En un entorno real habría que establecer una línea base y documentar las excepciones.
7. **La regla 100111 puede ser ruidosa**, porque los actualizadores también borran tareas. Su nivel 5 refleja que es contexto para una investigación, no una alerta por sí sola.
8. **La prueba de la tarea `-cmd` con las reglas nuevas no se repitió.** Según el diseño debería activar la 100110, pero no se ha verificado.

---

## 8. Lecciones aprendidas

- **Visibilidad no es lo mismo que detección.** Sysmon tenía toda la información en el endpoint desde el principio, pero ninguna regla la convertía en una alerta.
- **Una alerta con la descripción equivocada puede despistar más que la falta de alerta.** La 92004 habría llevado a un analista a buscar una consola `cmd.exe` que nunca existió. Hay que verificar el campo real (`image`) y no fiarse solo de la descripción.
- **La política de auditoría de Windows determina qué se puede detectar.** Revisarla forma parte de la incorporación de cualquier endpoint.
- **Las expresiones regulares dentro de reglas XML no pueden contener `<` ni `&` literales.** Se escriben como `\x3c` y `\x26`.
- **Validar siempre con `wazuh-analysisd -t` antes de reiniciar el Manager**, y hacer una copia de seguridad antes de cada cambio. Las dos medidas evitaron una interrupción del servicio.
- **Elevar la severidad de forma selectiva:** subir el nivel solo cuando el contexto lo justifica reduce el ruido sin perder visibilidad.

---

## 9. Filas para la matriz de pruebas

| ID | Escenario | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E3-A | Crear tarea con `schtasks` (sin auditoría) | T1053.005 | Sysmon 1, 11 | Alguna detección de la tarea | Solo 92004 (4) por coincidencia casual | ❌ Brecha |
| E3-B | Crear tarea con `schtasks` (con auditoría) | T1053.005 | Seguridad 4698 | 60228 (4) | 60228 (4) | ✅ Superado |
| E3-C1 | Tarea benigna (`notepad.exe`) | T1053.005 | Seguridad 4698 | 60228 (4) | 60228 (4) | ✅ Superado |
| E3-C2 | Tarea con LOLBin (`powershell.exe`) | T1053.005 | Seguridad 4698 | 100110 (10) | 100110 (10) | ✅ Superado |
| E3-C3 | Tarea desde `C:\Users\Public\` | T1053.005 | Seguridad 4698 | 100110 (10) | 100110 (10) | ✅ Superado |
| E3-C4 | Borrado de tareas | T1070 | Seguridad 4699 | 100111 (5) ×3 | 100111 (5) ×3 | ✅ Superado |

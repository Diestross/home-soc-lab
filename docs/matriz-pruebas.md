# Matriz de pruebas

Resumen consolidado de todas las pruebas de detección del laboratorio. Cada fila remite al caso donde se documentan el procedimiento, las evidencias y el análisis completo.

| Componente | Versión |
|---|---|
| Wazuh Manager / Indexer / Dashboard | 4.14.10-1 (All-in-One) |
| Wazuh Agent (Windows) | 4.14.10-1 |
| Sysmon | 15.22, configuración SwiftOnSecurity v74 |
| Endpoint | Windows 11 Pro, compilación 26300 |
| Servidor | Ubuntu Server 24.04.5 LTS (VirtualBox, 4 vCPU, 8 GB de RAM) |

**Leyenda de estados:**

| Estado | Significado |
|---|---|
| ✅ Superado | El resultado observado coincide con el esperado |
| ✅ Conforme | No se esperaba alerta (por diseño o por alcance) y no la hubo |
| ❌ Brecha | La actividad ocurrió y quedó registrada en el endpoint, pero **no generó una alerta útil** |
| ⚠️ Parcial | Hubo una detección indirecta, de bajo nivel, o un comportamiento que limita la detección |

---

## 1. Resumen

| Indicador | Valor |
|---|---|
| Escenarios planificados | 5 |
| Pruebas ejecutadas | 26 |
| ✅ Superadas o conformes | 19 |
| ❌ Brechas encontradas con el conjunto de reglas por defecto | 5 |
| ⚠️ Detecciones parciales | 2 |
| Reglas personalizadas creadas | 7 (100100, 100110, 100111, 100120, 100121, 100130, 100131) |
| Ajustes aplicados al endpoint | 3 permanentes + 1 temporal (ver [ajustes del endpoint](ajustes-endpoint.md)) |

**Conclusión principal:** con la configuración por defecto, Sysmon **registraba** la actividad de los cinco escenarios, pero en cuatro de ellos Wazuh **no generaba ninguna alerta útil**. La causa más frecuente fueron reglas base de **nivel 0** cuyas reglas hijas solo cubren variantes muy concretas. Visibilidad no equivale a detección.

---

## 2. Matriz completa

### Escenario 1 — Autenticación fallida · [Caso 1](casos/caso-01-autenticacion-fallida.md)

| ID | Prueba | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E1 | 10 inicios de sesión fallidos por SMB (usuario inexistente) | T1110 | Seguridad 4625 | 60122 ×9 + 60204 al 8.º fallo | 60122 ×9 + 60204 (10) al 8.º fallo | ✅ Superado |

### Escenario 2 — PowerShell con comando codificado · [Caso 2](casos/caso-02-powershell-encodedcommand.md)

| ID | Prueba | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E2-A | PowerShell → PowerShell `-EncodedCommand` | T1059.001 | Sysmon 1 | 92057 (12) | 92057 (12) | ✅ Superado |
| E2-B | PowerShell → PowerShell `-enc` (reglas por defecto) | T1059.001, T1027 | Sysmon 1 | 92057 (12) | 92027 (4) | ❌ Brecha |
| E2-B' | PowerShell → PowerShell `-enc` (con la regla 100100) | T1059.001, T1027 | Sysmon 1 | 100100 (12) | 100100 (12) | ✅ Superado |
| E2-C | PowerShell → PowerShell `-ec` (regresión) | T1059.001 | Sysmon 1 | 92057 (12) | 92057 (12) | ✅ Superado |

### Escenario 3 — Tareas programadas · [Caso 3](casos/caso-03-tarea-programada.md)

| ID | Prueba | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E3-A | Crear tarea con `schtasks` (sin auditoría) | T1053.005 | Sysmon 1, 11 | Alguna detección de la tarea | Solo 92004 (4), por coincidencia casual y con descripción incorrecta | ❌ Brecha |
| E3-B | Crear tarea con `schtasks` (con auditoría) | T1053.005 | Seguridad 4698 | 60228 (4) | 60228 (4) | ✅ Superado |
| E3-C1 | Tarea benigna (`notepad.exe`) | T1053.005 | Seguridad 4698 | 60228 (4) | 60228 (4) | ✅ Superado |
| E3-C2 | Tarea con LOLBin (`powershell.exe`) | T1053.005 | Seguridad 4698 | 100110 (10) | 100110 (10) | ✅ Superado |
| E3-C3 | Tarea desde `C:\Users\Public\` | T1053.005 | Seguridad 4698 | 100110 (10) | 100110 (10) | ✅ Superado |
| E3-C4 | Borrado de las tres tareas | T1070 | Seguridad 4699 | 100111 (5) ×3 | 100111 (5) ×3 | ✅ Superado |

### Escenario 4 — Claves Run del registro · [Caso 4](casos/caso-04-claves-run.md)

| ID | Prueba | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E4-A | Valor `notepad.exe` en HKCU/HKLM `Run` (reglas por defecto) | T1547.001 | Sysmon 13 | Alguna alerta | Ninguna (92300 de nivel 0) | ❌ Brecha |
| E4-B1 | Valor benigno en HKCU `Run` | T1547.001 | Sysmon 13 | 100120 (7) | 100120 (7) | ✅ Superado |
| E4-B2 | Valor con LOLBin oculto en HKCU `Run` | T1547.001 | Sysmon 13 | 100121 (12) | 100121 (12) | ✅ Superado |
| E4-B3 | Valor con ruta `\Users\Public\` en HKCU `Run` | T1547.001 | Sysmon 13 | 100121 (12) | 100121 (12) | ✅ Superado |
| E4-B4 | Eventos `RunNotification` de `sihost.exe` | — | Sysmon 13 | Ninguna alerta | Ninguna | ✅ Conforme |
| E4-C1 | FIM tras reiniciar el agente | T1547.001 | FIM | 752 | Ninguna (el primer escaneo crea la línea base) | ⚠️ Parcial |
| E4-C2 | Valor en HKLM `Run`, escaneos cada 5 min | T1547.001 | FIM | 752 (5) | 752 (5), 4 min 43 s después | ✅ Superado |
| E4-C3 | Valor en HKCU `Run`, escaneos cada 5 min | T1547.001 | FIM | Ninguna (fuera de alcance) | Ninguna | ✅ Conforme |
| E4-C4 | Borrado del valor en HKLM `Run` | T1547.001 | FIM | 751 (5) | 751 (5), 1 min 13 s después | ✅ Superado |

### Escenario 5 — Conexiones de red · [Caso 5](casos/caso-05-conexiones-red.md)

| ID | Prueba | Técnica | Fuente | Regla esperada | Resultado observado | Estado |
|---|---|---|---|---|---|---|
| E5-A0 | PowerShell → Internet (reglas por defecto) | T1071.001, T1105 | Sysmon 3, 22 | Alguna alerta | Ninguna (92101 y 61650 de nivel 0) | ❌ Brecha |
| E5-B0 | PowerShell → red interna:22 (reglas por defecto) | Reconocimiento | Sysmon 3 | Alguna alerta | Ninguna (92101 de nivel 0) | ❌ Brecha (se mantiene) |
| E5-C0 | `bitsadmin /transfer` (reglas por defecto) | T1197, T1105 | Sysmon 1, 22 · Sistema 7040 | Alguna alerta | Solo 61104 (3), indirecta | ⚠️ Parcial |
| E5-A1 | PowerShell → Internet (con la regla 100131) | T1071.001, T1105 | Sysmon 3 | 100131 (6) | 100131 (6) | ✅ Superado |
| E5-B1 | PowerShell → red interna:22 (con la regla 100131) | Reconocimiento | Sysmon 3 | Ninguna (exclusión por diseño) | Ninguna | ✅ Conforme |
| E5-C1 | `bitsadmin /transfer` (con la regla 100130) | T1197, T1105 | Sysmon 1 | 100130 (10) | 100130 (10) + 61104 (3) | ✅ Superado |

---

## 3. Brechas del conjunto de reglas por defecto

| Brecha | Escenario | Causa raíz | Estado |
|---|---|---|---|
| `-enc` no activa la regla de PowerShell codificado | E2 | La expresión regular de la 92057 no incluye la abreviatura `enc` | Corregida (100100) |
| La creación de tareas programadas no genera alerta | E3 | Auditoría de "Otros eventos de acceso a objetos" desactivada; ninguna regla trata `schtasks.exe` desde Sysmon | Corregida (auditoría + 100110) |
| La regla 92004 describe una consola `cmd` que no existió | E3 | Busca `\cmd.exe` en la línea de comandos, no en la imagen del proceso | Documentada |
| Valores en claves `Run` sin alerta | E4 | La regla base 92300 tiene nivel 0 y sus hijas solo cubren `.lnk`/`.vbs`, `reg.exe` y VNC | Corregida (100120, 100121) |
| Conexiones de PowerShell a Internet sin alerta | E5 | La regla base 92101 tiene nivel 0; las hijas solo cubren los puertos 135 y 389 | Corregida (100131) |
| Descargas con BITS sin alerta | E5 | La conexión la hace `svchost.exe`, que Sysmon no registra; no hay regla para `bitsadmin` | Corregida parcialmente (100130) |
| Las consultas DNS nunca generan alerta | E5 | La única regla del evento 22 (61650) tiene nivel 0 | Abierta |
| Reconocimiento interno desde PowerShell | E5 | 92101 de nivel 0; la 100131 excluye las IP privadas por diseño | Abierta |
| Borrado de valores en claves `Run` | E4 | El evento 12 de Sysmon no tiene regla | Abierta (el FIM lo detecta en HKLM, con retraso) |

---

## 4. Reglas personalizadas

Definidas en [`configs/wazuh/local_rules.xml`](../configs/wazuh/local_rules.xml).

| ID | Nivel | Cuelga de | Detecta | Técnica | Caso |
|---|---|---|---|---|---|
| 100100 | 12 | 92027 | PowerShell lanza PowerShell con cualquier abreviatura de `-EncodedCommand` | T1059.001, T1027 | 2 |
| 100110 | 10 | 60228 | Tarea programada cuya acción es un LOLBin o una ruta escribible por usuarios | T1053.005 | 3 |
| 100111 | 5 | 60103 | Tarea programada eliminada (evento 4699) | T1070 | 3 |
| 100120 | 7 | 92300 | Valor escrito en `Run`/`RunOnce`/`RunOnceEx`/`RunServices*` (excluye `RunNotification`) | T1547.001 | 4 |
| 100121 | 12 | 100120 | El valor anterior apunta a un LOLBin o a una ruta escribible por usuarios | T1547.001 | 4 |
| 100130 | 10 | `sysmon_event1` | `bitsadmin.exe` crea un trabajo de transferencia | T1197, T1105 | 5 |
| 100131 | 6 | 92101 | PowerShell abre una conexión TCP hacia una IP pública | T1071.001, T1105 | 5 |

**Criterios comunes de diseño:**

- Colgar la regla de la regla de serie que ya reconoce el evento (`if_sid`), en lugar de crear una regla hermana, para no depender del orden de evaluación de Wazuh.
- Elevar la severidad solo cuando el contexto lo justifica (LOLBins, rutas escribibles, IP públicas), para no multiplicar el ruido.
- Validar con `wazuh-analysisd -t` y hacer copia de seguridad antes de cada reinicio del Manager.
- Probar cada regla con al menos un caso positivo, un caso benigno y, cuando hay regla de serie, una prueba de regresión.

---

## 5. Cobertura por técnica de MITRE ATT&CK

| Técnica | Nombre | Cobertura tras el laboratorio | Reglas |
|---|---|---|---|
| T1110 | Brute Force | ✅ Fallos de inicio de sesión desde una misma IP | 60122, 60204 |
| T1059.001 | PowerShell | ✅ Comandos codificados (PowerShell → PowerShell) | 92057, 100100 |
| T1027 | Obfuscated Files or Information | ⚠️ Solo Base64 en la línea de comandos de PowerShell | 100100 |
| T1053.005 | Scheduled Task | ✅ Con auditoría activada; severidad elevada para acciones sospechosas | 60228, 100110 |
| T1070 | Indicator Removal | ⚠️ Solo el borrado de tareas programadas | 100111 |
| T1547.001 | Registry Run Keys | ✅ Claves `Run` (Sysmon, en tiempo real) · ⚠️ Carpeta de inicio no probada | 100120, 100121, 752, 751 |
| T1071.001 | Web Protocols | ⚠️ Solo PowerShell hacia IP públicas | 100131 |
| T1105 | Ingress Tool Transfer | ⚠️ PowerShell y `bitsadmin`; otros LOLBins sin cubrir | 100130, 100131 |
| T1197 | BITS Jobs | ⚠️ Solo mediante `bitsadmin.exe` | 100130 |

---

## 6. Observaciones transversales

| Observación | Casos |
|---|---|
| El propio agente de Wazuh genera unas 66 alertas por ciclo de SCA (verdaderos positivos benignos). Ajuste pendiente | 0 |
| La sincronización horaria del endpoint condiciona la correlación: un desfase de 16 s llevó a conclusiones erróneas | 1 |
| La descripción de una regla puede no corresponder a lo ocurrido; hay que verificar los campos del evento | 3 |
| El FIM solo detecta cambios entre dos escaneos consecutivos sin reinicio del agente | 4 |
| Las fuentes de telemetría exponen datos personales (SID, usuario, aplicaciones, nombre del equipo); hay que sanitizar las evidencias | 3, 4, 5 |

# Inventario y clasificación de vulnerabilidades del contenedor · CenfoPay (semana 2)

## 1. Inventario (SBOM)
- Archivo: `reportes/sbom-cyclonedx.json`   - Archivo: `reportes/antes/sbom-cyclonedx.json` · Componentes totales: 512
- Imagen base: `python:3.9` · Digest: `sha256:9ba52efd57b65fe914ffa64c04d8faf32c56ac802c6a164581816d71b0449edd`
- Sistema operativo y versión: Debian Bookworm · Paquetes del SO: 14.646 hallazgos registrados por Trivy · Librerías Python: 49 hallazgos registrados por Trivy· Componentes totales: ____Componentes totales: 512
- Imagen base: ________________  · Digest: `sha256:________________`
- Sistema operativo y versión: __________  · Paquetes del SO: ____  · Librerías Python: ____

## 2. Clasificación (antes / después del endurecimiento)
| Origen | Severidad | Antes | Después | Con corrección | Sin corrección | En CISA KEV |
|--------|-----------|------:|--------:|---------------:|---------------:|------------:|
| SO (trivy-so) | CRITICAL | | | | | |
| SO (trivy-so) | HIGH | | | | | |
| Dependencias (trivy-dependencias) | CRITICAL | | | | | |
| Dependencias (trivy-dependencias) | HIGH | | | | | |
| Configuración (trivy-config / hadolint) | ALTA | | | | | |
| Origen | Severidad | Antes | Después | Con corrección | Sin corrección | En CISA KEV |
|--------|-----------|------:|--------:|---------------:|---------------:|------------:|
| SO (trivy-so) | CRITICAL | 236 | 0 | 0 | 0 | 0 |
| SO (trivy-so) | HIGH | 2648 | 0 | 0 | 0 | 0 |
| Dependencias (trivy-dependencias) | CRITICAL | 1 | 1 | 0 | 1 | 0 |
| Dependencias (trivy-dependencias) | HIGH | 16 | 18 | 0 | 18 | 0 |
| Configuración (trivy-config / hadolint) | ALTA | 0 | 0 | 0 | 0 | 0 |
## 3. Top 5 para priorizar
| CVE | Paquete | CVSS | EPSS | ¿KEV? | ¿Se usa la función vulnerable? | Prioridad |
|-----|---------|------|------|-------|--------------------------------|-----------|
| | | | | | | |
| CVE | Paquete | CVSS | EPSS | ¿KEV? | ¿Se usa la función vulnerable? | Prioridad |
|-----|---------|------|------|-------|--------------------------------|-----------|
| CVE-2020-14343 | PyYAML | 9.8 | 0.04% | No | Sí | 1 |
| CVE-2024-34069 | Werkzeug | 7.5 | 0.10% | No | Sí | 2 |
| CVE-2024-1135 | Gunicorn | 7.5 | 0.05% | No | Sí | 3 |
| CVE-2023-30861 | Flask | 7.5 | 0.03% | No | Sí | 4 |
| CVE-2021-33503 | urllib3 | 7.5 | 0.02% | No | Sí | 5 |
## 4. Selección de la imagen base
| Criterio | Opción A | Opción B | Opción C |
|----------|----------|----------|----------|
| Imagen | `python:3.9` (actual) | | |
| Mantenida / con soporte | | | |
| Tamaño (MB) | | | |
| Vulnerabilidades C/H | | | |
| Tiene shell / gestor de paquetes | | | |
| Origen verificado (oficial, firmado) | | | |
| Compatibilidad con la app | | | |
| **Decisión y justificación** | | | |
| Criterio | Opción A | Opción B | Opción C |
|----------|----------|----------|----------|
| Imagen | `python:3.9` | `python:3.9-slim-bookworm` | `python:3.9-alpine` |
| Mantenida / con soporte | Python 3.9 dejó de recibir soporte en octubre de 2025 | Python 3.9 dejó de recibir soporte en octubre de 2025 | Python 3.9 dejó de recibir soporte en octubre de 2025 |
| Tamaño (MB) | Mayor | Menor | Menor |
| Vulnerabilidades C/H | Más | Menos | Puede variar |
| Tiene shell / gestor de paquetes | Sí | Sí | No incluye shell completo |
| Origen verificado (oficial, firmado) | Sí | Sí | Sí |
| Compatibilidad con la app | Compatible | Compatible | Puede requerir ajustes |
| **Decisión y justificación** | No seleccionada: imagen completa con mayor superficie de ataque | **Seleccionada**: menor tamaño, menos componentes y compatibilidad con CenfoPay | No seleccionada: puede causar problemas de compatibilidad con librerías compiladas |
## 5. Verificación post-endurecimiento
Pega aquí la salida de `bash scripts/verificar-endurecimiento.sh cenfopay:local cenfopay-app-1`.
El control END-02 quedó en ✅ porque la imagen final no contiene secretos reales en sus variables de entorno. La variable `GPG_KEY` es una clave pública utilizada por Python para verificar la integridad de sus descargas; no es una credencial ni un secreto.

```text
[i] Imagen: cenfopay:local
✅ END-01 La imagen define un usuario no root (USER)       USER=10001:10001
✅ END-02 Sin secretos en variables ENV de la imagen       ninguna variable sensible
✅ END-03 HEALTHCHECK definido                             presente
❌ END-04 Tamaño de la imagen <= 250 MB                   312 MB (superficie de ataque mayor)
❌ END-05 Sin herramientas innecesarias en runtime         encontradas: apt-get __sin_shell__
[i] Contenedor en ejecución: cenfopay-app-1
✅ END-06 Sistema de archivos raíz de solo lectura        read_only: true
✅ END-07 Capacidades Linux eliminadas (cap_drop ALL)      [ALL]
✅ END-08 no-new-privileges activo                         activo
✅ END-09 Contenedor no privilegiado                       privileged=false
✅ END-10 Puertos publicados solo en 127.0.0.1             127.0.0.1:8000 
✅ END-11 El proceso corre con UID distinto de 0           uid=10001
✅ END-12 Límite de memoria definido                      256 MB
[✓] Resultados en reportes/endurecimiento.json
```

END-04 y END-05 quedaron en ❌, pero son controles de severidad MEDIA. La compuerta de seguridad se mantiene en ✅ porque el umbral configurado para el endurecimiento es de 0 hallazgos de severidad ALTA, y no hay fallas ALTA. El tamaño de 312 MB y la presencia de `apt-get` se documentan como riesgos residuales de la imagen base `python:3.9-slim-bookworm`.
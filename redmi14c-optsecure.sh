#!/data/data/com.termux/files/usr/bin/bash
# redmi_opt_secure.sh
# Redmi 14C (Android 14) — Optimización + checks antispyware + interfaz
# Requiere: termux-api, nmap (opcional), jq (opcional). Muchas operaciones requieren Shizuku o ADB shell.
# Autor: Mohammed & ChatGPT (adaptado)

set -euo pipefail

# ----------------- CONFIG -----------------
LOGDIR="/sdcard/redmi_secure_opt"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/run.log"
APP_SUSPICIOUS_LIST="$LOGDIR/suspicious_apps.csv"
SLEEP_DAEMON=900   # tiempo en segundos entre ciclos si activas daemon (15 min)
# permisos que consideramos "peligrosos" o de alto riesgo
DANGEROUS_PERMS=(
  "READ_SMS" "RECEIVE_SMS" "SEND_SMS" "READ_CALL_LOG" "WRITE_CALL_LOG"
  "READ_CONTACTS" "WRITE_CONTACTS"
  "RECORD_AUDIO" "CAMERA"
  "ACCESS_FINE_LOCATION" "ACCESS_COARSE_LOCATION"
  "REQUEST_INSTALL_PACKAGES" "SYSTEM_ALERT_WINDOW"
  "BIND_ACCESSIBILITY_SERVICE" "READ_PHONE_STATE"
)
# paquetes protegidos que NO tocar
DO_NOT_TOUCH=( "com.android.systemui" "com.android.settings" "com.google.android.gms" "com.google.android.gsf" "com.miui.home" "com.android.phone" )

# ----------------- UTIL -----------------
ts(){ date "+%Y-%m-%d %H:%M:%S"; }
log(){ echo "[$(ts)] $*" | tee -a "$LOG"; }
has(){ command -v "$1" >/dev/null 2>&1; }

# comprobar si pm funciona (permiso)
pm_ok(){
  if pm list packages >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

need_shizuku_note(){
  if ! pm_ok; then
    echo
    echo "⚠️  AVISO: Muchos comandos pm fallarán si no ejecutas este script con permisos."
    echo " - Ejecuta con Shizuku (permite a Termux usar pm) o"
    echo " - Conéctate desde PC con ADB y ejecuta: adb shell sh ~/redmi_opt_secure.sh"
    echo
  fi
}

# instalar dependencias mínimas
install_deps(){
  log "Comprobando dependencias..."
  local miss=()
  for p in termux-api jq nmap; do
    if ! has "$p"; then miss+=("$p"); fi
  done
  if [ ${#miss[@]} -gt 0 ]; then
    echo "Paquetes faltantes: ${miss[*]}"
    read -p "¿Instalarlos ahora? (y/N) " yn
    if [[ "${yn,,}" = "y" || "${yn,,}" = "yes" ]]; then
      pkg update -y
      for m in "${miss[@]}"; do
        case "$m" in
          termux-api) pkg install -y termux-api ;;
          jq) pkg install -y jq ;;
          nmap) pkg install -y nmap ;;
          *) pkg install -y "$m" ;;
        esac
      done
    fi
  fi
}

# ----------------- FUNCS DE RENDIMIENTO -----------------
quick_boost(){
  log "Iniciando Boost rápido: detener apps intensas y reducir animaciones"
  # detener apps de foreground alto (heurística)
  if has top; then
    # detecta procesos con %CPU > 12 (heurístico)
    top -n 1 | awk 'NR>7{if($9>12) print $NF}' | sort -u | while read -r pkg; do
      # limpieza solo si parece paquete
      if [[ "$pkg" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        if [[ ! " ${DO_NOT_TOUCH[*]} " =~ " ${pkg} " ]]; then
          am force-stop "$pkg" >/dev/null 2>&1 && log "Detenido proceso caliente: $pkg"
        fi
      fi
    done
  fi

  # reducir animaciones
  settings put global window_animation_scale 0.5 || true
  settings put global transition_animation_scale 0.5 || true
  settings put global animator_duration_scale 0.5 || true

  pm trim-caches 999M >/dev/null 2>&1 || true
  log "Boost rápido finalizado"
}

deep_clean(){
  log "Limpieza profunda: trim caches + limpiar caches clave"
  pm trim-caches 999M >/dev/null 2>&1 || true
  # limpiar caches de candidatos (no crítico si falla)
  for pkg in com.google.android.gms com.google.android.webview; do
    pm clear "$pkg" >/dev/null 2>&1 && log "Limpiada cache: $pkg" || true
  done
  # limpiar temporales en sdcard (solo contenido de cache)
  if [ -d "/sdcard/Android/data" ]; then
    find /sdcard/Android/data -maxdepth 3 -type d -name cache -print0 2>/dev/null | while IFS= read -r -d '' d; do
      rm -rf "${d:?}/"* 2>/dev/null || true
    done
    log "Caches de /sdcard/Android/data limpiados (si existían)"
  fi
  # BG dexopt job para mejorar apertura de apps (si está disponible)
  cmd package bg-dexopt-job >/dev/null 2>&1 && log "bg-dexopt-job lanzado"
  log "Limpieza profunda completada"
}

# ----------------- FUNCS DE SEGURIDAD (HEURÍSTICAS) -----------------
list_third_party_apps(){
  # lista apps instaladas por usuario (paquetes de terceros)
  pm list packages -3 | sed 's/package://g' || true
}

list_disabled_apps(){
  pm list packages -d 2>/dev/null | sed 's/package://g' || true
}

app_installer(){
  local pkg="$1"
  pm list packages -i "$pkg" 2>/dev/null | sed -n 's/package:\(.*\) from://p' || true
}

# analiza permisos de una app y cuenta cuantos pertenecen al listado DANGEROUS_PERMS
analyze_app_perms(){
  local pkg="$1"
  # dumpsys package may require permissions
  local perms
  perms=$(dumpsys package "$pkg" 2>/dev/null | awk '/requestedPermissions/ {p=1; next} p && /^$/ {exit} p {gsub(/[][]|,/, ""); print}' | tr '\n' ' ')
  echo "$perms"
}

is_suspicious_by_perms(){
  local pkg="$1"
  local perms
  perms=$(analyze_app_perms "$pkg")
  local score=0
  for dp in "${DANGEROUS_PERMS[@]}"; do
    if echo "$perms" | grep -qw "$dp"; then
      ((score++))
    fi
  done
  # heurística: 2 o más permisos "peligrosos" => marcar
  if [ "$score" -ge 2 ]; then
    echo "$score"
    return 0
  else
    echo "0"
    return 1
  fi
}

detect_accessibility_services(){
  # buscar apps que tengan servicios de accesibilidad registrados
  dumpsys accessibility 2>/dev/null | awk '/Service/ {print $0}' || true
}

check_installer(){
  local pkg="$1"
  local installer
  installer=$(pm list packages -i "$pkg" 2>/dev/null | awk -F: '{print $2}' | tr -d '\r\n' || true)
  # alternative approach
  installer=$(pm list packages -i "$pkg" 2>/dev/null | sed -n 's/package://p' || true)
  echo "$installer"
}

scan_suspicious_apps(){
  log "Escaneando apps de usuario para comportamientos sospechosos..."
  echo "timestamp,package,installer,perm_count,suspicious_perms" > "$APP_SUSPICIOUS_LIST"
  for pkg in $(list_third_party_apps); do
    [ -z "$pkg" ] && continue
    # evitar tocar paquetes protegidos
    if [[ " ${DO_NOT_TOUCH[*]} " =~ " ${pkg} " ]]; then
      continue
    fi
    installer=$(pm list packages -i "$pkg" 2>/dev/null | sed -n 's/installerPackageName=//p' || true)
    # prefer simple: check installer via pm
    installer_name=$(pm list packages -i "$pkg" 2>/dev/null || true)
    perms=$(analyze_app_perms "$pkg")
    suspicious_score=$(is_suspicious_by_perms "$pkg")
    # log if suspicious_score >=2
    if [ "$suspicious_score" -ge 2 ]; then
      echo "$(ts),$pkg,${installer_name//,/},$suspicious_score,\"$(echo "$perms" | tr ' ' ';')\"" >> "$APP_SUSPICIOUS_LIST"
      log "⚠️ App sospechosa: $pkg (score $suspicious_score)"
    fi
  done
  log "Escaneo de apps completado. Resultado: $APP_SUSPICIOUS_LIST"
}

# ----------------- RED / CONEXIONES -----------------
list_active_connections(){
  log "Listando conexiones activas (si se dispone de ss/netstat)..."
  if has ss; then
    ss -tunp 2>/dev/null | sed -n '1,80p' || true
  elif has netstat; then
    netstat -tunp 2>/dev/null | sed -n '1,80p' || true
  else
    log "ss/netstat no disponibles. Instala iproute2 o net-tools."
  fi
}

# ----------------- CONGELAR / DESHACER -----------------
freeze_package(){
  local pkg="$1"
  if [[ " ${DO_NOT_TOUCH[*]} " =~ " ${pkg} " ]]; then
    echo "❌ Paquete protegido, no se congela: $pkg"
    return
  fi
  pm clear "$pkg" >/dev/null 2>&1 || true
  pm disable-user --user 0 "$pkg" >/dev/null 2>&1 && log "🧊 Congelado: $pkg" || echo "⚠️ No se pudo congelar $pkg (¿Shizuku/ADB requerido?)"
}

unfreeze_package(){
  local pkg="$1"
  pm enable "$pkg" >/dev/null 2>&1 && log "🔓 Habilitado: $pkg" || echo "⚠️ No se pudo habilitar $pkg"
}

# ----------------- DAEMON (opcional) -----------------
daemon_loop(){
  termux-wake-lock || true
  log "Daemon iniciando (cada ${SLEEP_DAEMON}s). Usa Ctrl+C para detener."
  while true; do
    quick_boost
    scan_suspicious_apps
    # opcional: limpiar caches ligeros
    pm trim-caches 512M >/dev/null 2>&1 || true
    sleep "$SLEEP_DAEMON"
  done
}

# ----------------- MENU -----------------
menu(){
  need_shizuku_note
  install_deps
  while true; do
    clear
    echo "=============================================="
    echo "  Redmi14C — Optimización & Seguridad (Termux)"
    echo "  Logs: $LOGDIR"
    echo "=============================================="
    echo "1) 🔥 Boost rápido (cerrar apps y animaciones)"
    echo "2) 🧹 Limpieza profunda (caches, temp)"
    echo "3) 🕵️‍♂️ Escanear apps sospechosas (permisos/instalador)"
    echo "4) 📡 Comprobar conexiones de red activas"
    echo "5) 🧊 Congelar app (pm disable-user)"
    echo "6) 🔓 Habilitar app (pm enable)"
    echo "7) 📋 Listar apps de usuario (3rd-party)"
    echo "8) 📋 Listar apps deshabilitadas"
    echo "9) ▶️ Ejecutar daemon (auto mantenimiento)"
    echo "0) ❌ Salir"
    echo "----------------------------------------------"
    read -rp "Elige opción: " opt
    case "$opt" in
      1) quick_boost; read -rp "Enter para volver..." ;;
      2) deep_clean; read -rp "Enter para volver..." ;;
      3) scan_suspicious_apps; echo "Listado guardado en $APP_SUSPICIOUS_LIST"; read -rp "Enter para ver el archivo..." && { sed -n '1,200p' "$APP_SUSPICIOUS_LIST"; read -rp "Enter para volver..."; } ;;
      4) list_active_connections; read -rp "Enter para volver..." ;;
      5) read -rp "Paquete a congelar (ej com.example.app): " p && freeze_package "$p" && read -rp "Enter para volver..." ;;
      6) read -rp "Paquete a habilitar (ej com.example.app): " p && unfreeze_package "$p" && read -rp "Enter para volver..." ;;
      7) list_third_party_apps | sed -n '1,200p'; read -rp "Enter para volver..." ;;
      8) list_disabled_apps | sed -n '1,200p'; read -rp "Enter para volver..." ;;
      9) echo "Iniciando daemon... (Ctrl+C para parar)"; daemon_loop ;;
      0) echo "Saliendo..."; exit 0 ;;
      *) echo "Opción inválida"; sleep 1 ;;
    esac
  done
}

# ----------------- MAIN -----------------
main(){
  log "Inicio de ejecución"
  menu
}

main "$@"

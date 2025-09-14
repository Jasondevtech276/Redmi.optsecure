# Redmi14C-OptSecure — Optimización & Seguridad (Termux)

Un **script todo-en-uno** para Termux diseñado para exprimir el rendimiento y reforzar la seguridad básica de un **Redmi 14C (HyperOS / Android 14)** sin root.  

Incluye optimizaciones de rendimiento, heurísticas antispyware/antimalware, limpieza de caché, gestión de apps (congelar/habilitar), y utilidades de red básicas.  
Puede usarse con **Shizuku** o **ADB** cuando se requieran permisos elevados.

---

## ✨ Características
- 🔋 **Boost rápido**: libera RAM, mata procesos innecesarios, ajusta animaciones.  
- 🧹 **Limpieza profunda**: borra cachés de sistema y apps, trim de almacenamiento.  
- 🔒 **Escaneo antispyware**: identifica apps con permisos sospechosos.  
- 📦 **Gestión de apps**: congelar / habilitar paquetes de sistema y usuario.  
- ⚡ **Daemon opcional**: mantenimiento automático y periódico.  
- 📂 **Logs detallados**: guardados en `/sdcard/redmi_secure_opt/`.  

---

## ✅ Requisitos
- Termux actualizado  
- Permisos de almacenamiento (`termux-setup-storage`)  
- Recomendado: **Shizuku** o conexión **ADB**  
- Paquetes: `termux-api`, `jq`, `nmap` (opcional para funciones de red)  

---

## 🛠 Instalación
```bash
pkg update && pkg upgrade -y
pkg install -y git termux-api jq nmap
termux-setup-storage
git clone https://github.com/Jasondevtech276/Redmi.optsecure
cd Redmi14C-OptSecure/scripts
chmod +x *.sh
./redmi_opt_secure.sh

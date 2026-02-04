# 🌊 TorrentFlow v2.5

![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web_App-000000?style=flat&logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)

**TorrentFlow** es la solución definitiva para gestionar tu servidor de descargas casero. Olvídate de interfaces complejas; aquí tienes un diseño limpio, moderno y responsivo conectado directamente a la potencia de **qBittorrent**.

---

## 🔥 Novedades de la v2.5
* ✨ **Nuevo diseño UI/UX:** Interfaz "Stitch" oscura mejorada con TailwindCSS.
* 🛡️ **Roles de Usuario:** Crea administradores y usuarios estándar.
* 📧 **Perfiles Completos:** Soporte para email, teléfono y avatares automáticos.
* 🖥️ **Smart OS Detection:** La interfaz se adapta si corre en Docker (ocultando funciones de escritorio local).
* 📱 **Full Responsive:** Footer sticky y menús adaptables a móvil.

---

## 📸 Vista Previa

| **Dashboard** | **Gestión de Usuarios** |
|:---:|:---:|
| ![Dash](https://via.placeholder.com/400x250/101922/FFFFFF?text=Dashboard+Moderno) | ![Users](https://via.placeholder.com/400x250/101922/FFFFFF?text=Admin+Panel) |

---

## 🚀 Despliegue Rápido (Docker Compose)

Crea un archivo `docker-compose.yml` y ¡listo!

```yaml
version: '3.8'
services:
  torrentflow:
    image: basilioag/webtorrent:latest
    container_name: torrentflow
    restart: unless-stopped
    ports:
      - "5000:5000"
    volumes:
      - ./torrents.db:/app/torrents.db
    environment:
      - QBIT_HOST=192.168.1.XX  # IP de tu servidor qBittorrent
      - QBIT_PORT=8080
# 🕵️‍♂️ Packet Sniffer en Python

Este proyecto es un **sniffer de red** desarrollado en Python, pensado para capturar tráfico de red en tiempo real desde la terminal. Está diseñado con fines educativos y análisis básico, ideal para estudiantes o entusiastas de la ciberseguridad.

---

## ✨ Características

- Captura paquetes IP, TCP y UDP en tiempo real
- Muestra el tráfico con colores en la consola usando `colorama`
- Resume los paquetes capturados por protocolo al finalizar
- Guarda todos los paquetes capturados en un archivo `log.json`
- Funciona en Windows, macOS y Linux

---

## 📦 Requisitos

Instalá las dependencias con:

```bash
pip install scapy colorama
```

> En macOS y Linux es probable que necesites ejecutar el script con permisos de superusuario:

```bash
sudo python sniffer.py
```

---

## ▶️ Uso

```bash
python sniffer.py
```

Presioná `Ctrl + C` para detener la captura. Al hacerlo:

- Verás un resumen de los protocolos capturados
- Se guardará el log en `log.json`

---

## 📂 Estructura del proyecto

```
sniffer/
├── sniffer.py
├── log.json         # Se genera automáticamente
└── README.md
```

---

## 📊 Ejemplo de salida

```
[14:22:10] 192.168.0.1 → 8.8.8.8 (UDP)
[14:22:11] 192.168.0.1 → 142.250.78.14 (TCP)

Sniffer detenido por el usuario.

Resumen de paquetes capturados:
  TCP: 32 paquetes
  UDP: 9 paquetes

Log guardado en log.json
```

---

Este proyecto fue desarrollado únicamente con fines educativos.  
**No debe utilizarse para interceptar tráfico en redes ajenas o sin autorización.**  
El autor no se responsabiliza por el uso indebido de esta herramienta.




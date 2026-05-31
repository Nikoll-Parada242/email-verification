# Guardian de Correos 🛡️

**Guardian de Correos** es una aplicación de escritorio moderna y limpia escrita en Python para analizar el asunto y el contenido de un correo electrónico con el fin de determinar si es seguro o si contiene amenazas potenciales de **Phishing o Spam**.

La aplicación cuenta con una interfaz dinámica de ventana única basada en `tkinter` que transiciona fluidamente entre la pantalla de formulario y la pantalla de veredicto.

---

## 🚀 Requisitos de Ejecución

La aplicación está desarrollada usando exclusivamente la biblioteca gráfica estándar de Python (`tkinter`), por lo que **no requiere instalar dependencias adicionales** (sin necesidad de configurar entornos virtuales ni ejecutar `pip install`).

### Requisitos previos:
* Tener instalado **Python 3.8 o superior**.
  * *Nota para Windows:* Al instalar Python, recuerda marcar la opción **"Add Python to PATH"**.

---

## 💻 Instrucciones para Correr la Aplicación

Si descargas o clonas este proyecto en otra computadora, sigue estos pasos:

1. **Abre una terminal** (PowerShell, CMD o terminal de VS Code) y navega hasta la carpeta del proyecto.
2. Ejecuta el archivo principal `app.py` según tu sistema operativo:

### En Windows:
```bash
python app.py
```
*O alternativamente:*
```bash
py app.py
```

### En macOS y Linux:
```bash
python3 app.py
```

---

## ⚙️ Estructura del Proyecto

* **`app.py`**: Código fuente principal que contiene la lógica del analizador, los componentes interactivos personalizados de la interfaz y la gestión dinámica de pantallas.
* **`.gitignore`**: Configuración para excluir archivos basura y carpetas temporales (`__pycache__`, compilados, etc.) del control de versiones.
* **`Readme.md`**: Este archivo de documentación técnica.
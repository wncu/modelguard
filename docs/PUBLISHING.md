# Subir el proyecto

Repositorio creado: https://github.com/wncu/modelguard. La integración de esta sesión rechazó escrituras al repo nuevo. El paquete entregado contiene todos los archivos pendientes de subir.

```bash
git clone https://github.com/wncu/modelguard.git modelguard-repo
```

Copia el contenido de la carpeta modelguard del ZIP a modelguard-repo, conservando .git del clon. No copies el ZIP ni pesos de modelos.

```bash
cd modelguard-repo
python scripts/check.py
git add README.md LICENSE SECURITY.md CONTRIBUTING.md pyproject.toml .gitignore docs web scripts schemas modelguard tests
git commit -m "Add methodology, frontend and local scripts"
git push origin main
```

Alternativamente, habilita el repo nuevo en los permisos de la integración GitHub de ChatGPT para futuras escrituras. No compartas tokens en chat.

Para el frontend, sirve web/ en un hosting estático. Esta entrega no habilita GitHub Pages ni workflows de despliegue. La URL del repo no es una app desplegada. Antes de publicar verifica visualmente layout móvil, teclado, errores CORS, selección de archivos, importación y exportación.

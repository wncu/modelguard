# Publicar y distribuir

## Web (estática)

`web/` no necesita servidor de aplicación: son archivos estáticos (`index.html`, `app.js`, `engine.mjs`, `style.css`). Opciones:

- **GitHub Pages:** Pages solo publica desde la raíz o `/docs` de una rama, así que publica `web/` en una rama propia y elígela en Settings → Pages (rama `gh-pages`, carpeta `/`):
  ```bash
  git subtree push --prefix web origin gh-pages
  ```
- **Cloudflare Pages / Netlify:** directorio de salida `web`, sin comando de build.
- **Local:** `python scripts/serve.py` (solo loopback).

El hosting debe servir `.mjs` como `text/javascript` (GitHub Pages, Cloudflare y `http.server` lo hacen). La política CSP de `index.html` solo permite scripts propios y conexiones a `https://huggingface.co`.

Antes de publicar: `python scripts/check.py` y una prueba manual con archivos reales en escritorio y móvil.

## CLI y MCP

Sin paquete en PyPI por ahora. Instalación desde GitHub:

```bash
pip install git+https://github.com/wncu/modelguard
claude mcp add modelguard -- modelguard mcp
```

Para publicar en PyPI: `python -m build` y `twine upload dist/*` con el nombre `modelguard-local` de `pyproject.toml`, tras subir la versión en `pyproject.toml` y `modelguard/__init__.py`.

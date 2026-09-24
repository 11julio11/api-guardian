# Matriz de Cabeceras HTTP y Configuración Defensiva de APIs

Esta referencia detalla las cabeceras recomendadas para APIs REST/GraphQL modernas tanto en entornos locales como de producción.

---

## 🛡️ Cabeceras Esenciales

| Cabecera | Valor Recomendado | Propósito / Mitigación |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Fuerza conexión HTTPS segura y mitiga ataques Man-in-the-Middle y SSL Stripping. |
| `X-Content-Type-Options` | `nosniff` | Previene que navegadores ignoren el Content-Type declarado (evita MIME confusion). |
| `X-Frame-Options` | `DENY` | Evita que las respuestas de la API sean embebidas en iframes (Clickjacking). |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Política estricta para respuestas de API que retornan JSON. |
| `Cache-Control` | `no-store, max-age=0` (para datos autenticados) | Impide que proxies intermedios o cachés de navegadores guarden datos confidenciales. |

---

## 🚫 Cabeceras a Deshabilitar o Eliminar

| Cabecera Insegura | Razón | Solución |
| :--- | :--- | :--- |
| `X-Powered-By: Express` | Fuga tecnología y runtime exacto del backend. | `app.disable('x-powered-by')` |
| `Server: Apache/2.4.41 (Ubuntu)` | Expone versión del servidor web. | En Nginx: `server_tokens off;` |
| `X-AspNet-Version` | Expone versión de .NET. | En `web.config`: `enableVersionHeader="false"` |

---

## 🌐 Configuración Defensiva de CORS

### Caso 1: API Privada de Aplicación Web (Con Autenticación por Cookies/Tokens)
```http
Access-Control-Allow-Origin: https://app.tuempresa.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
```
> [!CAUTION]
> **Nunca** combines `Access-Control-Allow-Origin: *` con `Access-Control-Allow-Credentials: true`. La mayoría de navegadores lo bloquean por especificación, pero reflejar dinámicamente el `Origin` recibido con credenciales activadas representa una vulnerabilidad crítica de robo de sesión.

### Caso 2: API Pública / Consumo de Datos Abiertos
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Headers: Content-Type
```
*(Solo si el endpoint es completamente anónimo y no procesa información privada de usuarios).*

# OWASP API Security Top 10 (2023) - Guía Práctica de Auditoría y Remediación

Esta guía es la base de conocimiento utilizada por **API Guardian** para clasificar y remediar vulnerabilidades en el código de endpoints y contratos de API.

---

### API1:2023 - Broken Object Level Authorization (BOLA / IDOR)
* **Descripción:** Ocurre cuando un endpoint acepta un identificador de objeto (ej. `/api/v1/orders/:id`) y accede a dicho objeto sin verificar si el usuario autenticado tiene permisos para interactuar con él.
* **Impacto:** Fuga y manipulación masiva de datos entre distintos usuarios o empresas (multi-tenancy breach).
* **Patrón Vulnerable:**
  ```javascript
  // Express / Node.js
  app.get('/api/orders/:orderId', authenticate, async (req, res) => {
    const order = await Order.findById(req.params.orderId); // ❌ Vulnerable a BOLA
    res.json(order);
  });
  ```
* **Patrón Seguro:**
  ```javascript
  app.get('/api/orders/:orderId', authenticate, async (req, res) => {
    const order = await Order.findOne({
      where: {
        id: req.params.orderId,
        customerId: req.user.id // ✅ Validar pertenencia del objeto
      }
    });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
  });
  ```

---

### API2:2023 - Broken Authentication
* **Descripción:** Mecanismos de autenticación deficientes, falta de protección contra ataques de fuerza bruta, tokens débiles o credenciales en query strings.
* **Impacto:** Suplantación de cuentas y robo de sesiones administrativas.
* **Patrón Vulnerable:**
  ```text
  GET /api/v1/reports?api_key=secret12345 HTTP/1.1  // ❌ Parámetros sensibles en URL
  ```
* **Patrón Seguro:**
  ```text
  GET /api/v1/reports HTTP/1.1
  Authorization: Bearer <JWT_O_API_KEY>  // ✅ Transmisión en cabecera protegida
  ```

---

### API3:2023 - Broken Object Property Level Authorization (BOPLA / Mass Assignment)
* **Descripción:** Permitir que los clientes modifiquen propiedades de objetos que no deberían alterar (ej. `role: admin`, `balance: 99999`) o exponer datos privados que el cliente no necesita (`ssn`, `password_hash`).
* **Impacto:** Escalada de privilegios y corrupción de datos de negocio.
* **Patrón Vulnerable:**
  ```python
  # FastAPI / Django / Flask
  @app.post("/users")
  async def create_user(request: Request):
      data = await request.json()
      user = User.objects.create(**data)  # ❌ Inyección de campos restringidos
      return user
  ```
* **Patrón Seguro:**
  ```python
  # Usar esquemas tipados con campos estrictos (Pydantic / DTO)
  class UserCreateDTO(BaseModel):
      username: str
      email: EmailStr
      # Excluir 'is_admin', 'role', 'balance' del esquema público

  @app.post("/users")
  async def create_user(dto: UserCreateDTO):
      user = User.objects.create(username=dto.username, email=dto.email)  # ✅
      return user
  ```

---

### API4:2023 - Unrestricted Resource Consumption
* **Descripción:** Falta de límites en el tamaño de subidas de archivos, número de elementos solicitados en colecciones o frecuencia de peticiones (rate limiting).
* **Impacto:** Denegación de servicio (DoS), agotamiento de memoria y costos desorbitados de computación/nube.
* **Remediación:**
  * Forzar paginación con un límite superior estricto (`limit = Math.min(requestedLimit, 100)`).
  * Limitar tamaño de payloads en el framework (ej. `express.json({ limit: '1mb' })`).
  * Aplicar Rate Limiting a nivel de IP y token de usuario (`express-rate-limit`, Redis token bucket).

---

### API5:2023 - Broken Function Level Authorization (BFLA)
* **Descripción:** Usuarios regulares pueden invocar endpoints diseñados para administradores cambiando el método HTTP o la ruta (ej. `DELETE /api/users/123` o `POST /api/admin/reboot`).
* **Remediación:**
  * Adoptar el principio de mínimo privilegio.
  * Usar guardias y decoradores de roles consistentes:
    ```typescript
    @UseGuards(AuthGuard, RolesGuard)
    @Roles('SUPER_ADMIN')
    @Delete(':id')
    async deleteTenant(@Param('id') id: string) { ... }
    ```

---

### API6:2023 - Unrestricted Access to Sensitive Business Flows
* **Descripción:** Flujos sensibles (comprar entradas, transferir saldo, publicar reseñas, solicitar códigos SMS) expuestos a automatización abusiva por bots.
* **Remediación:** Captchas defensivos, análisis de reputación de IP, limitación de frecuencia por flujo de negocio.

---

### API7:2023 - Server Side Request Forgery (SSRF)
* **Descripción:** La API acepta una URL proporcionada por el usuario (webhooks, carga de avatars remotos) y realiza la petición sin validar el destino.
* **Impacto:** Acceso a servicios internos de la nube (ej. `http://169.254.169.254/computeMetadata/v1/` en GCP o AWS).
* **Remediación:**
  * Validar dominios contra una lista blanca estricta.
  * Deshabilitar redirecciones automáticas.
  * Bloquear rangos de IP privadas (RFC 1918) y direcciones de metadatos de proveedores cloud.

---

### API8:2023 - Security Misconfiguration
* **Descripción:** Mensajes de error con stack traces, cabeceras HTTP inseguras, CORS permisivo (`Origin: *` con credenciales), TLS desactualizado.
* **Remediación:**
  * Deshabilitar `X-Powered-By`.
  * Utilizar HSTS y `X-Content-Type-Options: nosniff`.
  * Middleware global de errores que capture excepciones y retorne un UUID de seguimiento sin exponer detalles del código.

---

### API9:2023 - Improper Inventory Management
* **Descripción:** APIs huérfanas, versiones antiguas o deprecadas (ej. `/api/v1/` que no tiene parches de seguridad junto a `/api/v3/`).
* **Remediación:** Documentar y dar de baja versiones antiguas, centralizar el catálogo de APIs.

---

### API10:2023 - Unsafe Consumption of APIs
* **Descripción:** Confiar ciegamente en datos provenientes de APIs de terceros sin sanitizarlos antes de procesarlos o reenviarlos.
* **Remediación:** Validar respuestas de terceros con esquemas estrictos antes de procesarlas en la lógica de negocio.

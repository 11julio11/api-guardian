# Protocolo de 3 Fases (Análisis, Plan, Ejecución)

Esta regla se aplica de forma estricta a cualquier tarea o requerimiento en este proyecto. El agente NUNCA debe escribir código de producción sin antes pasar por las fases 1 y 2.

## FASE 1: Análisis (Filtro 1)
- El agente debe leer el código, investigar dependencias y entender el contexto del requerimiento.
- NO se permite modificar código fuente ni ejecutar comandos que alteren el estado del sistema.
- Entregable: Un resumen claro de lo que se encontró y cómo se abordará el problema.

## FASE 2: Plan Detallado (Filtro 2)
- El agente DEBE generar un plan estructurado (ej. implementation_plan.md y 	ask.md) detallando exactamente qué archivos se van a modificar y qué lógica se va a alterar con base en la Fase 1.
- **ALTO OBLIGATORIO:** El agente debe detener su ejecución aquí y hacer explícita la solicitud de aprobación: *"Espero tu 'OK' para proceder con la ejecución"*.
- El agente NO PUEDE avanzar a la Fase 3 sin que el usuario diga explícitamente que aprueba el plan.

## FASE 3: Ejecución (Filtro 3)
- Solo tras la aprobación del plan, el agente implementará el código.
- El agente debe seguir estrictamente lo acordado en la Fase 2, marcando las tareas completadas.
- Al finalizar, el agente presentará los resultados listos para su validación (ej. walkthrough.md).

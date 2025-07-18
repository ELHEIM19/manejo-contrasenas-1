## Manejo de contraseñas en Python

Este proyecto contiene ejemplos de cómo manejar contraseñas de manera segura en Python utilizando diferentes métodos de encriptación.

### Métodos incluidos

1. **Encriptado con SHA-512 y sal**
    - Archivo: `encriptado.py`
    - Este método utiliza SHA-512 para encriptar contraseñas y un valor de sal (salt) para mejorar la seguridad.

    > **Nota:** En la base de datos debes guardar tanto la contraseña encriptada como el valor de la sal (`salt`).

2. **Encriptado con bcrypt**
    - Archivo: `encriptado_bcrypt.py`
    - Este método utiliza la biblioteca `bcrypt`, que maneja automáticamente la generación de sal y es más resistente a ataques de fuerza bruta.

### Requisitos

Para ejecutar los ejemplos, asegúrate de tener instalada la siguiente biblioteca:

```bash
pip install bcrypt
```

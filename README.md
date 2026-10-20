# Extractor local para TP-Link XGB430v Pro ESDIGI

CLI interactiva para consultar las credenciales que figuran en el backup de un router propio. El programa principal es un único archivo: `digi_credentials.py`.

## Compatibilidad y requisitos

- Python 3.9 o posterior, con soporte SSL.
- Una terminal interactiva para introducir la contraseña sin mostrarla.
- Acceso al panel web del router desde la red local y una cuenta válida.
- **Una sola** de estas bibliotecas criptográficas funcionales:

| Paquete de Python | Módulo que importa el programa |
| --- | --- |
| `cryptography` | `cryptography` |
| `pycryptodomex` | `Cryptodome` |
| `pycryptodome` | `Crypto` |

No es necesario instalar las tres. El programa prueba los módulos en el orden de la tabla. El resto de sus dependencias pertenece a la biblioteca estándar de Python; no necesita `requests`, un navegador ni un controlador web.

Está adaptado al **TP-Link XGB430v Pro ESDIGI**, con ProductID decimal `1083710977` y el protocolo de firmware descrito más abajo. No es una herramienta universal para cualquier TP-Link. Si detecta un protocolo o formato desconocido, se detiene.

## Comprobar dependencias

La comprobación está integrada en el programa principal. Desde su carpeta, ejecuta:

```sh
python digi_credentials.py
```

**Antes de preguntar la IP, el usuario o la contraseña y antes de realizar conexiones**, el programa verifica la versión de Python, busca una biblioteca criptográfica compatible y comprueba AES-CBC, DES-ECB y MD5 con vectores conocidos. Si todo está disponible, continúa directamente con las preguntas.

Si falta una biblioteca, muestra el comando que debes ejecutar y termina con código `1`, sin comenzar las preguntas:

```sh
python -m pip install cryptography
```

Si la biblioteca está instalada pero falla la prueba criptográfica, indica un comando para repararla. **La comprobación no descarga ni instala nada y no guarda informes.** Ejecuta el comando indicado con el mismo intérprete que utilizas para el extractor y después vuelve a iniciar el programa.

`requirements.txt` declara `cryptography` como dependencia predeterminada. Si ya funciona `pycryptodomex` o `pycryptodome`, puedes omitir la instalación. Si no tienes ninguna, puedes instalar la predeterminada manualmente:

```sh
python -m pip install -r requirements.txt
```

Como alternativa, instala **solo uno** de estos paquetes:

```sh
python -m pip install pycryptodomex
```

```sh
python -m pip install pycryptodome
```

La instalación manual con `pip` normalmente descarga paquetes de su repositorio configurado. El extractor no ejecuta estos comandos ni descarga dependencias por su cuenta.

En sistemas donde el intérprete se llama `python3`, sustituye `python` por `python3` en todos los comandos.

## Uso

Ejecuta el programa sin parámetros:

```sh
python digi_credentials.py
```

Introduce la IP numérica del router, tu usuario habitual y tu contraseña. La contraseña se solicita mediante `getpass`, sin eco. Si no hay una terminal que permita ocultarla, el programa se detiene.

Cierra antes otras sesiones del panel web: el programa se detiene si detecta una sesión abierta u ocupada. No reintenta contraseñas.

El flujo es:

1. Comprobar las dependencias locales antes de comenzar las preguntas.
2. Solicitar la IP y comprobar el protocolo de acceso servido por el router.
3. Solicitar el usuario y la contraseña e iniciar sesión.
4. Determinar la ruta de backup a partir de la página del firmware y sus metadatos.
5. Descargar, descifrar, verificar MD5 y descomprimir exclusivamente en memoria.
6. Mostrar únicamente los pares de usuario y contraseña de Admin, PPPoE y SIP.
7. Intentar cerrar la sesión.

## Privacidad y resultados

Las conexiones del extractor van exclusivamente a la IP introducida, en los puertos web estándar. No usa DNS, proxies, navegador, telemetría, cargas de archivos ni redirecciones. Prefiere HTTPS y acepta el certificado autofirmado del router; si HTTPS no está disponible, prueba HTTP antes de pedir credenciales.

No guarda backups, XML, cookies, contraseñas ni registros. Los datos se procesan en memoria y las credenciales se muestran en la terminal. Python no controla la paginación de memoria del sistema ni las grabaciones externas de la terminal.

Después de los mensajes de progreso, el resultado tiene este formato:

```text
Admin user: xxxx
Admin password: xxxx

PPPoE user: xxxx
PPPoE password: xxxx

SIP user: xxxx
SIP password: xxxx
```

Las entidades XML se decodifican una vez, por ejemplo `&#37;` se muestra como `%`. Un campo ausente aparece como `(no disponible)` y uno oculto como `(oculto)`. Si hay varias cuentas igualmente prioritarias, se muestra `(varios)` en lugar de elegir una al azar. No se inventan credenciales SIP.

## Detalles del formato compatible

- El login obtiene parámetros de `/cgi/getGDPRParm` y envía un mensaje JSON de `/cgi/login`, cifrado con AES-CBC, mediante `POST /cgi_gdpr?9`. La firma utiliza RSA sin padding y MD5 de usuario + contraseña.
- La fórmula de `/main/backNRestore.htm` utiliza modelo, versión mayor, fecha/hora de compilación, indicador de firma y sufijos Aginet. Los metadatos se consultan mediante los objetos de lectura `DEV2_DEV_INFO` y, cuando corresponde, `DEV2_SYS_CFG`. No se prueban nombres de archivo al azar.
- La clave DES-ECB se deriva de `748da50bf93e2dcf` XOR los ocho bytes ASCII de `40981e01`, la representación hexadecimal del ProductID `1083710977`.
- MD5 se verifica antes de descomprimir. La descompresión LZSS limita el tamaño de salida y admite la longitud en ambos órdenes de bytes.
- El lector admite el XML particular del firmware, incluidos atributos sin comillas, entidades y valores multilínea.

## Validación

Se ha probado el flujo completo en un XGB430v Pro ESDIGI: login, determinación automática de la ruta, descarga, DES, MD5, LZSS y análisis de campos. La compatibilidad puede cambiar entre versiones de firmware.

Las pruebas realizadas también cubren vectores DES/AES, comparación RSA con el JavaScript del router mediante datos ficticios, archivos dañados, separación de categorías de credenciales, ausencia de SIP, fórmula de descarga, flujo HTTP simulado, rechazo de destinos externos y ausencia de reintentos después de un error de contraseña.

## Archivos

| Archivo | Función |
| --- | --- |
| `digi_credentials.py` | Extractor interactivo con comprobación de dependencias integrada. |
| `requirements.txt` | Dependencia predeterminada para instalación manual con `pip`. |
| `README.md` | Requisitos, uso y límites de compatibilidad. |

## Referencias y licencia

- [tpconf_bin_xml, Alain Ducharme](https://github.com/sta-c0000/tpconf_bin_xml): formato y algoritmo de compresión.
- [tplink-firmware-tools](https://github.com/jqssun/tplink-firmware-tools): derivación de clave a partir del ProductID.
- Protocolo web y fórmula de backup contrastados con los scripts servidos por el firmware.

El extractor se distribuye bajo GPL-3.0-or-later, con atribución al algoritmo de `tpconf_bin_xml`. [Texto de la licencia](https://www.gnu.org/licenses/gpl-3.0.html).

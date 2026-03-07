# Encryption Design

## Selected AEAD Algorithm

Para el sistema de cifrado de

este avance se eligió utilizar AES-GCM.

Este algoritmo pertenece a la

categoría de AEAD (Authenticated Encryption with Associated Data).

La razón por la cual nosotros

elegimos AES-GCM es que permite proporcionar confidencialidad e integridad al

mismo tiempo. Es decir, no solo cifra la información del archivo, sino que

también genera un authentication tag que permite detectar si el contenido fue

modificado.

---

## Key Size

Para el cifrado se utiliza una

clave simétrica de 256 bits.

El tamaño de 256 bits se

eligió porque proporciona un alto nivel de seguridad contra ataques de fuerza

bruta. Actualmente, este tamaño de clave es considerado seguro para proteger

información sensible durante muchos años.

La clave se genera utilizando

un generador de números aleatorios criptográficamente seguro proporcionado por

el sistema operativo.

---

## Nonce Strategy

El algoritmo AES-GCM requiere

el uso de un nonce (Number Used Once) para cada operación de cifrado.

En este caso se genera un

nonce de 96 bits (12 bytes) utilizando un generador de números aleatorios

seguro. Este nonce se genera de forma nueva para cada archivo cifrado.

El nonce se almacena junto con

el ciphertext dentro del contenedor cifrado, ya que es necesario para poder

realizar el proceso de descifrado posteriormente.

El nonce nunca se tiene que

repetir con la misma clave, ya que esto podría comprometer la seguridad del

cifrado.

---

## Metadata Authentication Strategy

El sistema incluye metadatos

asociados al archivo cifrado, los cuales son:

- nombre del archivo
- versión del algoritmo
- timestamp de creación

Estos metadatos no se cifran,

pero sí se autentican utilizando Associated Authenticated Data (AAD).

Esto significa que los

metadatos se incluyen en el proceso de autenticación del algoritmo AEAD. Si un

atacante modifica cualquier parte de los metadatos, el authentication tag

dejará de ser válido y el descifrado fallará.

De esta manera se evita que

los metadatos puedan ser modificados sin ser detectados.

---

# Security Decisions

## Why AEAD instead of encryption + hash?

La razón es que AEAD integra

confidencialidad e integridad en un solo algoritmo seguro, evitando errores de

implementación que pueden ocurrir cuando se combinan primitivas criptográficas

manualmente.

Si se utilizara cifrado más

hash por separado, podrían surgir problemas como:

- verificar el hash en el orden incorrecto
- olvidar autenticar ciertos datos

Los algoritmos AEAD ya están

diseñados para evitar estos problemas, por lo que su uso reduce

significativamente el riesgo de errores de seguridad.

---

## What happens if nonce repeats?

Si el mismo nonce se reutiliza

con la misma clave en AES-GCM, la seguridad del sistema puede romperse.

La reutilización de nonce

puede permitir a un atacante derivar información sobre el contenido de los

archivos cifrados, lo que podría comprometer la confidencialidad de los datos.

Además, también puede afectar

la seguridad del mecanismo de autenticación, permitiendo ataques que modifiquen

los datos sin ser detectados.

Por esta razón, en el sistema

se genera un nonce nuevo y aleatorio para cada operación de cifrado.

---

## What attacker are you defending against?

El sistema está diseñado para

proteger los archivos contra atacantes que obtienen acceso al contenedor

cifrado, pero que no poseen la clave privada o la clave simétrica correcta.

Entre los escenarios

considerados se encuentran:

- un atacante que obtiene acceso al almacenamiento donde se guardan los contenedores cifrados
- un atacante que intenta modificar el contenido del archivo cifrado
- un atacante que intenta modificar los metadatos del archivo
- un atacante que intenta descifrar el archivo sin la clave correcta

En todos estos casos, el

sistema debe garantizar que:

- el contenido del archivo no pueda ser leído sin la clave correcta
- cualquier modificación del archivo o metadatos sea detectada
- el descifrado falle si la autenticidad de los datos no es válida

---

# Pruebas

A continuación, se muestran

las pruebas realizadas con pytest cuyos archivos se encuentran en la carpeta

tests, donde se realizaron las siguientes pruebas, primero de manera indivual y

finalmente de manera conjunta un test tras otro.

---

## test_encrypt_decrypt

![img1](images/img1.png)

---

## test_llave_erronea

![img2](images/img2.png)

---

## test_texto_modificado

![img3](images/img3.png)

---

## test_metadata_modificada

![img4](images/img4.png)

---

## test_encriptaciones_multiples

![img5](images/img5.png)

---

Y finalmente se corrieron

todos los tests de forma conjunta:

![img6](images/img6.png)

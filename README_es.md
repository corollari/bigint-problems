% Problemas al tratar con números enteros grandes % Albert % 2019
\newpage
\setcounter{tocdepth}{4} \tableofcontents
\newpage

## Introducción al problema
Actualmente estamos construyendo un puente entre Binance Chain y NEO, uno de los componentes de dicho puente es un programa alojado en NEO que verifica los bloques de Binance Chain, y parte de la verificación de estos bloques incluye la verificación de varias [firmas de Schnorrf](https://en.wikipedia.org/wiki/Schnorr_signature) que fueron creadas utilizando el [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519). Así que resumiendo, necesitamos implementar un programa que verifique las firmas del Ed25519 dentro de NeoVM, que es la máquina virtual usada en NEO.

## Entorno
NeoVM, el entorno en el que se ejecutará el algoritmo es especial debido a las restricciones asociadas a él:
- Opera con números de 256 bits firmados, lo que significa que puede operar directamente sobre números que pertenecen^[_De hecho creo que esta suposición no ha sido probada_] puede operar sobre números que son marginalmente más grandes, debido a que puede almacenar los números en _two's complement_ pero eso no debería cambiar nada, ya que sólo permite que un número más sea representado, de €(2^255, -2^255)€.
- La multiplicación, la adición, la suma, el módulo, la división de números enteros y todas las operaciones de números estándar  son soportadas y tienen todas el mismo coste computacional.
- La VM (máquina virtual) es [turing completa](https://en.wikipedia.org/wiki/Turing_completeness), por lo que es posible utilizar bucles y condicionales.
- Si alguna operación matemática resulta en un _underflow_ o _overflow_ la ejecución completa se detiene y la VM falla, por lo tanto a través de toda la ejecución del algoritmo debemos asegurarnos de que nunca suceda esto. Por ejemplo, si se intenta calcular `(a*b)%p` con números grandes fallará porque el resultado intermedio `a*b` se desbordará, ocurrira un _overflow_. También cabe destacar, que es imposible comprobar si hay _overflows/underflows_ después de que hayan ocurrido, ya que para entonces la VM ya habrá fallado y no soporta el manejo de _excepciones_.
-Las operaciones tienen los siguientes costos, todos los precios están en GAS, que es aproximadamente equivalente a USD. (Mirar tabla).

| Operación | Coste |
|-----------|------|
| Almacenar 1KB en memoria permanente | 1 |
| Leer dato en memoria permanente | 0.1 |
| Todas las otras operaciones | 0.001 |
 
Esta diferencia de costes significa que si tomamos un conjunto de opcodes (_códigos de operación_) que pueden ser ejecutados en 1 segundo en un procesador Intel Core i7 6950X de 3GHz (lanzado en 2016) y en su lugar los ejecutamos dentro del NeoVM, el coste de esa ejecución^[IPS/ciclo de reloj tomado los datos de https://en.wikipedia.org/wiki/Instructions\_per\_second#Timeline\_of_instructions\_per_second] será de 3*10^9*106*0.001=318.000.000 de GAS y alrededor de la misma cantidad en USD. Por lo tanto, está claro que el coste de ejecutar código dentro de NeoVM es masivamente caro y requeriremos una amplia optimización. Encontrar alternativas a este problemas será la principal motivación del presente texto.

## Algoritmo
Implementación en Python del algoritmo de verificación^[Fuente: https://tools.ietf.org/html/rfc8032#section-6]:
```python
## Primero, algunos preliminares que serán necesarios.

import hashlib

def sha512(s):
    return hashlib.sha512(s).digest()

# Z_p, Z modulo p con p primero (es un cuerpo (Z_p,+,*))
p = 2**255 - 19

def modp_inv(x):
    return pow(x, p-2, p)

# Constante de la curva
d = -121665 * modp_inv(121666) % p

#Orden de grupo
q = 2**252 + 27742317777372353535851937790883648493

def sha512_modq(s):
    return int.from_bytes(sha512(s), "little") % q

## A continuación, sigue una serie de funciones para realizar operaciones puntuales.

“””
Los puntos se representan como tuplas (X, Y, Z, T) de la extensión
coordenadas, con x = X/Z, y = Y/Z, x*y = T/Z
“””

def point_add(P, Q):
    A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;
    E, F, G, H = B-A, D-C, D+C, B+A;
    return (E*F, G*H, F*G, E*H);

# Calculamos Q = s * Q
def point_mul(s, P):
    Q = (0, 1, 1, 0)  # Elemento neutro respecto la
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q

def point_equal(P, Q):
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True

#Ahora sigue las funciones para la _compresión de puntos_

# Raíz cuadrada de -1 --> unidad imaginaria
modp_sqrt_m1 = pow(2, (p-1) // 4, p)

"""
Calcular la coordenada x correspondiente, con el bit bajo
correspondiente a la  firmar o bien devolver Ninguno en caso de fallo
"""

def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Calcular la raíz cuadrada de x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x

# Punto base
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)

def point_compress(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression") #Longitud de entrada inválida para la descompresión
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)

## Y finalmente las funciones de verificación

def verify(public, msg, signature):
    if len(public) != 32:
        raise Exception("Bad public key length") # Mala/incorrecta clase pública
    if len(signature) != 64:
        Exception("Bad signature length") #Longitud incorrecta para la firma
    A = point_decompress(public)
    if not A:
        return False
    Rs = signature[:32]
    R = point_decompress(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q: return False
    h = sha512_modq(Rs + public + msg)
    sB = point_mul(s, G)
    hA = point_mul(h, A)
    return point_equal(sB, point_add(R, hA))
```
## Soluciones
Empezaremos explicando varias soluciones generales y luego pasaremos a soluciones para problemas más específicos.

### Desplazando operaciones fuera de la cadena de bloques
Dado que el algoritmo de verificación de firmas proporcionado anteriormente estaba pensado para ser ejecutado de forma aislada y funcionar de forma autónoma,es posible optimizar enormemente varias partes del mismo debido a que sólo necesitamos verificar que la firma es correcta, por lo tanto estamos trabajando con requisitos más débiles que eliminan la necesidad de que el código trabaje de forma aislada.
Esto significa que es posible, ejecutar cualquier código en _entornos locales_ fuera de NeoVM y luego utilizar los resultados obtenidos para ayudar a la ejecución del contrato inteligente, con un asequible y mucho menor.

Un ejemplo de las optimizaciones que se pueden lograr usando este método se puede encontrar en el cálculo de `modp_inv`. Esta función en concreto, que encuentra el inverso de un número en el _cuerpo_ €Z_p€, se implementa usando una [exponencial modular](https://en.wikipedia.org/wiki/Modular_exponentiation) con un exponente considerablemente grande, se ejecutará en un tiempo €\mathcal{O}{log(n)}€ usando los mejores algoritmos.Esto significa que requerirá como mínimo 255 iteraciones de operaciones matemáticas costosas, lo que claramente hace que toda la operación sea realmente cara.

Alternativamente, es posible ejecutar ese código fuera de NeoVM y luego simplemente enviar el resultado a NeoVM junto con el resto de las variables  para cuando se ejecuta la prueba, en ese momento el código que se ejecuta dentro de NeoVM puede simplemente realizar la comparación `(a*inv)%p==1` y verificar que el inverso proporcionado es correcto y seguir con la ejecución, evitando el gasto de ejecutar `modp_inv`.

A través de este sencillo mecanismo hemos trasladado parte del cálculo desde dentro de la NeoVM a fuera de ella, reduciendo el número de operaciones necesarias por un factor de 255.

Esta misma técnica es aplicable a otras partes del algoritmo, aunque todavía estamos buscando formas de aplicarla a las partes más caras  del código (mirar tabla de la sección anterior): Operaciones ECC como `point_mul` y `point_add`, [SHA512](https://en.wikipedia.org/wiki/SHA-2) y otras operaciones más elementales como el módulo o la multiplicación modular.

### Verificación de desafío-respuesta
Otra posible solución que puede reducir el coste enormemente, pasa por la construcción de un protocolo basado en retos en torno a la verificación de pruebas. Esto funcionará colocando la carga de demostrar que la prueba es errónea en la contraparte del protocolo.

Dado el siguiente algoritmo:
```python
def verify(A)
    B = computeB(A)
    C = computeC(B)
    if C == 1:
        return True
    else:
        return False
```
Un protocolo que utilice el mecanismo explicado se implementaría de la siguiente manera:
1. Alicia pide una prueba a Bob
2. Bob ejecuta el código en su computadora y sube los resultados intermedios `A`, `B` y `C` al _smart contract_.
3. Alice llama al _smart contract_ y afirma que la transición de `B` a `C` fue incorrecta, por lo tanto la prueba no resulta  válida.
4. El _smart contract_ ejecuta el càlculo `computeC(B)` en el interior de la máquina virtual de NEO (NeoVM) utilizando el valor `B` dado por Bob, y  compara el resultado con el  valor `C` dado por Bob. Si resultan ser iguales  implicará que Alice ha mentido y será penalizada, mientras que si son diferentes, Bob será penalizado por dar pruebas falsas.

Comprobamos que través de ese protocolo hemos reducido el número de operaciones a computar, ya que inicialmente `computeB` y `computeC` siempre tenían que ser ejecutadas, mientras que con el nuevo protocolo sólo es necesario ejecutar una.
Con este método cualquier cálculo puede dividirse en partes, después se cargan sus diferentes estados intermedios y  por tanto finalmente sólo se ejecuta una transición entre estados en NeoVM.
La corrección se puede comprobar gracias al hecho de que si un cálculo es correcto todos los estados intermedios y las transiciones entre ellos deben ser correctas, y si no hay una transición incorrecta entre estados eso implica que todo el proceso es correcto.

El protocolo puede mejorarse aún más permitiendo que cualquiera reclame la no corrección de la prueba, construyendo mecanismos de incentivo (si alguien reclama que una prueba no es correcta y se descubre que tiene razón se le recompensa...) en torno a eso y separando el protocolo en varias rondas en las que se proporcionan más pruebas (por ejemplo: después de que Alicia reclame que la transición de B a C fue incorrecta, Bob subiría los diferentes estados entre B y C, de los cuales Alicia elegiría la transición no correcta y continuaría el protocolo).

La especificación del protocolo WIP (Work In Progress), que incluye más detalles sobre los protocolos de desafío-respuesta que planeamos implementar, está disponible en https://github.com/safudex/smartbnb/blob/collat/protocol.md.

### Suma y multiplicación modular (suma y producto de clases en el cuerpo)

En la ejecución de `point_mul` hay de 256 a 512 llamadas a la función `point_add`, que luego realiza varias operaciones de la forma `(a*b)%p` por lo tanto es muy importante optimizar eso tanto como sea posible.  Para ello desarrollamos el siguiente algoritmo para realizar sumas modulares:
```python
# Asumimos 0 < a, b < p
def modsum(a,b,p):
    k=a-p+b
    if(k<0):
        k+=p
    return k
```
Y luego construimos la multiplicación^[Fuente: https://www.geeksforgeeks.org/how-to-avoid-overflow-in-modular-multiplication/] iterando sobre los bits de uno de los números y aplicando sumas:

```python
# Asumimos 0 < a, b < mod
def mulmod(a, b, mod):
    res = 0;
    while (b > 0):
        # If b is odd, add 'a' to result
        if (b % 2 == 1):
            res = modsum(res, a,  mod);
 
        # Multiplicar 'a' por 2
        a = modsum(a , a, mod);
 
        # Dividir 'b' por dos
        b //= 2;

    return res
```

Sin embargo, este procedimiento es realmente caro ya que el bucle se repetirá probablemente cerca de 255 veces, y la realización de los _modsums_ de cada iteración es también bastante costosa.

En general, la implementación de `point_add` usando estos algoritmos resulta en un coste de ejecución de 213 GAS, lo que hace que el coste total de los dos `point_mul` sea de alrededor de 100.000 GAS.

Se puede tomar un enfoque diferente usando varias palabras de 256 bits para mantener los resultados intermedios, y luego realizar la clásica multiplicación larga^[https://en.wikipedia.org/wiki/Multiplication\_algorithm#Long\_multiplication] y el modulo.  El siguiente código realiza una versión optimizada de esto^[Fuente: https://github.com/trezor/trezor-crypto/blob/master/bignum.c]:
```C
/* función auxiliar para la multiplicación
 * calcular k * x como un número de 540 bit en base 2^30 (normalizado).
 * asumimos que k y x están normalizados. */
void bn_multiply_long(const bignum256 *k, const bignum256 *x,
                      uint32_t res[18]) {
  int i, j;
  uint64_t temp = 0;

  // calcular la mitad inferior de la multiplicación larga
  for (i = 0; i < 9; i++) {
    for (j = 0; j <= i; j++) {
      // no hay overflow, ya que 9*2^60 < 2^64
      temp += k->val[j] * (uint64_t)x->val[i - j];
    }
    res[i] = temp & 0x3FFFFFFFu;
    temp >>= 30;
  }
 // computar la mitad superior
  for (; i < 17; i++) {
    for (j = i - 8; j < 9; j++) {
     // no hay overflow, ya que 9*2^60 < 2^64
      temp += k->val[j] * (uint64_t)x->val[i - j];
    }
    res[i] = temp & 0x3FFFFFFFu;
    temp >>= 30;
  }
  res[17] = temp;
}

/* función auxiliar para la múltiplicación
* reducir res a  z modulo prime, con prime primero es cuerpo
* asumimos i >= 8 y i <= 16
* asumimos  res normalizado, res < 2^(30(i-7)) * 2 * prime
* garantizar que  res  està normalizado, res < 2^(30(i-8)) * 2 * prime */
void bn_multiply_reduce_step(uint32_t res[18], const bignum256 *prime,
                             uint32_t i) {
  // k = i-8.
  // en la entrada:
  //  0 <= res < 2^(30k + 31) *prime
  // coeficiente estimado,  estimate coef = (res / prime / 2^30k)
  // by coef = res / 2^(30k + 256)  con reondeo a la baja
  // 0 <= coef < 2^31
  // substraer (coef * 2^(30k) * prime) de res
  // notesé que hemos desarollado la primera iteración.
  assert(i >= 8 && i <= 16);
  uint32_t j;
  uint32_t coef = (res[i] >> 16) + (res[i + 1] << 14);
  uint64_t temp =
      0x2000000000000000ull + res[i - 8] - prime->val[0] * (uint64_t)coef;
  assert(coef < 0x80000000u);
  res[i - 8] = temp & 0x3FFFFFFF;
  for (j = 1; j < 9; j++) {
    temp >>= 30;
    // Nota: coeff * prime->val[j] <= (2^31-1) * (2^30-1)
    // Por lo tanto, esta adición no se desbordará (underflow).
    temp +=
        0x1FFFFFFF80000000ull + res[i - 8 + j] - prime->val[j] * (uint64_t)coef;
    res[i - 8 + j] = temp & 0x3FFFFFFF;
    // 0 <= temp < 2^61 + 2^30
  }
  temp >>= 30;
  temp += 0x1FFFFFFF80000000ull + res[i - 8 + j];
  res[i - 8 + j] = temp & 0x3FFFFFFF;
  // Nos vasamos en el hecho que prime > 2^256 - 2^224
  //   res = oldres - coef*2^(30k) * prime;
  //  y
  //   coef * 2^(30k + 256) <= oldres < (coef+1) * 2^(30k + 256)
  // Por lo tanto, 0 <= res < 2^30k (2^256 + coef * (2^256 - prime))
  //                 < 2^30k (2^256 + 2^31 * 2^224)
  //                 < 2^30k (2 * prime)
}

// función auxiliar para la multiplicación.
// reducimos x = res modulo prime.
// assumimos res normalizado , res < 2^270 * 2 * prime
// garantizamos x parcialmente reducido, i.e., x < 2 * prime
void bn_multiply_reduce(bignum256 *x, uint32_t res[18],
                        const bignum256 *prime) {
  int i;
  // res = k * x  es un nùmero normalizado  (cada miembro < 2^30)
  // 0 <= res < 2^270 * 2 * prime.
  for (i = 16; i >= 8; i--) {
    bn_multiply_reduce_step(res, prime, i);
    assert(res[i + 1] == 0);
  }
  // guardamos el resultado
  for (i = 0; i < 9; i++) {
    x->val[i] = res[i];
  }
}

// Calculamos x := k * x  (mod prime, número primero)
// Ambas entradas deven ser menores que 180 * prime.
// EL resultado se reduce parcialmente ( 0 <= x < 2 * prime)
// This only works for primes between 2^256-2^224 and 2^256.
void bn_multiply(const bignum256 *k, bignum256 *x, const bignum256 *prime) {
  uint32_t res[18] = {0};
  bn_multiply_long(k, x, res);
  bn_multiply_reduce(x, res, prime);
  memzero(res, sizeof(res));
}
```
Dado que este algoritmo utiliza la clásica multiplicación larga, que tiene una complejidad de €\mathcal{O}{n^2}€ en la que €n€ es el número de trozos en que se divide un número para hacer las multiplicaciones.
Dado que el código proporcionado divide los números de 256 bits en 9 trozos de 30 bits, por lo que `bn_multiply_long` pasa por 81 iteraciones en sus bucles. Personalmente no entiendo por qué usan números de 30 bits y tienen un sistema de normalización extraño, así que siguiendo la [valla de Chesterton](https://en.wikipedia.org/wiki/Wikipedia:Chesterton%27s\_fence) no debería quitar eso, pero si pudiéramos quitarlo podríamos usar trozos de 86 bits y reducir el número total de operaciones a €3^2=9€ y luego aplicar el módulo, almacenando el resultado intermedio en 3 palabras de 256 bits diferentes.

## Recursos
Una lista de recursos que son bastante interesantes pero que aún no hemos explorado en profundidad:
- [Wikipedia: Multiplication Algorithms](https://en.wikipedia.org/wiki/Multiplication_algorithm)
- [Wikipedia: Arbitrary-precision arithmetic](https://en.wikipedia.org/wiki/Arbitrary-precision_arithmetic)
- [Wikipedia: Karatsuba algorithm](https://en.wikipedia.org/wiki/Karatsuba_algorithm)
- [Wikipedia: SHA2 Pseudocode](https://en.wikipedia.org/wiki/SHA-2#Pseudocode)
- [Book: BigNum Math: Implementing Cryptographic Multiple Precision Arithmetic](http://index-of.co.uk/Hacking-Coleccion/BigNum%20Math%20-%20Implementing%20Cryptographic%20Multiple%20Precision%20Arithmetic.pdf) 

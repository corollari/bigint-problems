% Problems when dealing with big integers
% Albert
% 2019

\newpage

\setcounter{tocdepth}{4}
\tableofcontents

\newpage

## Basic problem
We are currently building a bridge between Binance Chain and NEO, one of the components of such a bridge is a program hosted in NEO which verifies blocks from Binance Chain, and part of the verification of these blocks includes the verification of several Schnorr signatures that were created using Ed25519.
So, long story short, we need to implement a program that verifies Ed25519 signatures inside the NeoVM, the virtual machine used in NEO.

## Environment
NeoVM, the environment where the algorithm will be run is special due to the constraints associated with it:
- It operates with 256-bit signed numbers, meaning that it can operate directly on numbers that belong^[In fact I think (this assumption hasn't been tested) it can operate on numbers that are marginally larger due to the fact that it may store the numbers in two's complement but that shouldn't change anything, as it only allows for one more number to be represented] to €(2^255, -2^255)€.
- Multiplication, addition, sum, modulus, integer division and all the standard number operations are supported and have all the same cost.
- The VM is turing complete, so it's possible to use loops and conditionals.
- If any mathematical operation results in an underflow or overflow the whole execution is stopped and the VM faults, therefore through the whole execution of the algorithm we must make sure that it never happens, not even in intermediate results (eg: if you try to calculate `(a*b)%p` with large numbers it will fault because the intermediate result `a*b` will overflow). It's also impossible to check for overflows/underflows after they have ocurred as by then the VM will have already faulted and it does not support exception handling.
- Operations have the following costs, all prices are in GAS, which is roughly equivalent to USD.

| Operation | Cost |
|-----------|------|
| Store 1KB on permanent storage | 1 |
| Read permanent storage | 0.1 |
| All other operations | 0.001 |

This difference in costs means that if we take a set of opcodes that can be executed in 1 second in a 3GHz Intel Core i7 6950X processor (released in 2016) and instead execute them inside the NeoVM the cost of that execution^[IPS/clock cycle taken from https://en.wikipedia.org/wiki/Instructions\_per\_second#Timeline\_of\_instructions\_per\_second] will be €3*10^9*106*0.001=318,000,000€ GAS and around the same amount in USD. It is therefore clear that the cost of running code inside the NeoVM is massively expensive and will require extensive optimization.

## Algorithm
Python implementation of the verification algorithm^[Source: https://tools.ietf.org/html/rfc8032#section-6]:
```python
## First, some preliminaries that will be needed.

import hashlib

def sha512(s):
    return hashlib.sha512(s).digest()

# Base field Z_p
p = 2**255 - 19

def modp_inv(x):
    return pow(x, p-2, p)

# Curve constant
d = -121665 * modp_inv(121666) % p

# Group order
q = 2**252 + 27742317777372353535851937790883648493

def sha512_modq(s):
    return int.from_bytes(sha512(s), "little") % q

## Then follows functions to perform point operations.

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

def point_add(P, Q):
    A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;
    E, F, G, H = B-A, D-C, D+C, B+A;
    return (E*F, G*H, F*G, E*H);

# Computes Q = s * Q
def point_mul(s, P):
    Q = (0, 1, 1, 0)  # Neutral element
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

## Now follows functions for point compression.

# Square root of -1
modp_sqrt_m1 = pow(2, (p-1) // 4, p)

# Compute corresponding x-coordinate, with low bit corresponding to
# sign, or return None on failure
def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x

# Base point
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
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)

## And finally the verification function.

def verify(public, msg, signature):
    if len(public) != 32:
        raise Exception("Bad public key length")
    if len(signature) != 64:
        Exception("Bad signature length")
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

The function we need to be able to run is `verify`. It is also important to note that, except hashing, all the operations are performed in €Z_p€ where p is a prime (concretely €2^255 - 19€).

Now, while it's possible to directly implement the whole algorithm and run it every time, a simple implementation of `point_mul` costs 100,000 GAS to execute, which is currently valued at around 100,000 USD. Therefore it is clear that this is not a viable option, an other solutions must be explored to minimize the execution cost.

### Number distribution
It is important to note that, assuming that the numbers we will operate with are distributed randomly across the available space (€[0, 2^255-20]€), about half of those will be 255 bits in length, a quarter of them will be 254-bit long... Noticing that there is a huge disparity between the cardinalities of numbers with high bit-length and those with low bit-length is important because it rules out some possible optimizations like the the following modular multiplcation function:
```python
def modmult(a, b, p):
	if bitlength(a)<=64 and bitlength(b)<=64:
		return (a*b)%p
	else:
		return multAvoidOverflow(a, b, p)
```
The probability that a given number has a bit length lower than 64 (we need both numbers to be like that in order to avoid overflow in the intermediate result) is €sum^256_i=128 1/(2^i) ~= 10^-39€, so the probability of the first condition being true is €~10^-78€. Clearly that if conditional is slowing the algorithm more than it is making it faster, and the following implementation would be better:
```python
def modmult(a, b, p):
	return multAvoidOverflow(a, b, p)
```

## Solutions
We'll start by explaining several general solutions and then we'll move into solutions for specific problems.

### Moving operations offchain
Given that the signature verification algorithm provided before was meant to be run in isolation and work in a standalone way, it is possible to vastly optimize several parts of it due to the fact that we only need to verify that the signature is correct, therefore we are working with weaker requirements that drop the need for the code to work in isolation. This means that it is possible for us to run any code on local environments outside the NeoVM and then use the results obtained from that to help with the execution of the smart contract.

One example of the optimizations that can be achieved using this method can be found in the calculation of `modp_inv`. That function, which finds the inverse of a number in the field €Z_p€ and is implemented using modular exponentiation with a really large exponent, will run in €O(log p)€ using the best algorithms, meaning that it will require at the very minimum 255 iterations of expensive math, clearly making the whole operation really expensive. Alternatively, it is possible to run that code outside of NeoVM and then just send the result to the NeoVM along with the other variables when the proof is executed, at that point the code running inside the NeoVM can just perform the comparison `(a*inv)%p==1` and verify that the inverse provided is correct and go along with the execution, avoiding the expense of running `modp_inv`.
Through this simple mechanism we have moved some computation from inside the NeoVM to outside of it, reducing the number of operations needed by a factor of 255.

This same technique is applicable to other parts of the algorithm but we are still looking for ways to apply it to the most expensive parts: ECC operations such as `point_mul` and `point_add`, computing SHA512 and other smaller operations such as modulus or modular multiplication.

### Challenge-response verification
Another possible solution that can reduce the cost by a huge factor involves building a protocol based on challenges around the proof verification. This will work by placing the burden of showing that the proof is wrong on the protocol counterparty.

Given the following algorithm:
```python
def verify(A)
	B = computeB(A)
	C = computeC(B)
	if C == 1:
		return True
	else:
		return False
```

A protocol using the explained mechanism would be implemented in the following way:
1. Alice requests a proof from Bob
2. Bob runs the code on his computer and uploads intermediate results `A`, `B` and `C` to the smart contract
3. Alice calls the smart contract and claims that the transition from B to C was wrong, therefore the proof is invalid
4. The smart contract executes `computeC(B)` inside the NeoVM using the `B` provided by Bob and compares the result with the `C` also provided by Bob. If they are equal Alice has lied and will be punished whereas if they are different Bob will be punished for providing a fake proof.

Through that protocol we have reduced the number of operations to be computed, as initially `computeB` and `computeC` always had to be run while with the new protocol only one needs to be run.
Using this method any computation can be split into parts, then have it's different intermediate states uploaded and finally only one transition between states actually run on the NeoVM. Correctness can be proved thanks to the fact that if a computation is correct all the intermediate stages and the transitions between them should be correct, and if there is no incorrect transition between states that implies that the whole process is correct.

The protocol can be further improved by allowing anyone to claim non-correctness of the proof, building incentive mechanisms (if someone claims a proof is not correct and they are found to be right they are rewarded...) around that and separating the protocol into several rounds in which evidence is further provided (eg: after Alice claims that the transition from B to C was wrong, Bob would upload the different states between B and C, from which Alice would pick the non-correct transition and continue the protocol).

The WIP (Work In Progress) specification of the protocol, which includes more details on the challenge-response protocols that we plan o implementing is available at https://github.com/safudex/smartbnb/blob/collat/protocol.md.

### Modular multiplication & addition
In the execution of `point_mul` there are from 256 to 512 calls to `point_add`, which then performs several operations of the form `(a*b)%p`, therefore it is heavily important to optimize that as much as possible. In order to do that we developed the following algorithm to perform modular sums:
```python
# Assume 0 < a, b < p
def modsum(a,b,p):
    k=a-p+b
    if(k<0):
        k+=p
    return k
```

And then built the multiplication^[Source: https://www.geeksforgeeks.org/how-to-avoid-overflow-in-modular-multiplication/] by iterating over the bits of one of the numbers and applying sums:
```python
# Assume 0 < a, b < mod
def mulmod256(a, b, mod): 
    res = 0;
    while (b > 0): 
        # If b is odd, add 'a' to result 
        if (b % 2 == 1): 
            res = modsum(res, a,  mod); 
  
        # Multiply 'a' by 2 
        a = modsum(a , a, mod); 
  
        # Divide b by 2 
        b //= 2; 

    return res
```
Nevertheless this procedure is really expensive as the loop will probably repeat close to 255 times, and performing the modsums of each iteration is quite expensive aswell.
Overall, implementing `point_add` using these algorithms results in an execution cost of 213 GAS, bringing the total cost of the two `point_mul` to around 100,000 GAS.

Using the fact that `2**255%p=19` and that 19 only consists of 5 bits we can further optimize the algorithm by computing the sum with classical long multiplication^[https://en.wikipedia.org/wiki/Multiplication\_algorithm#Long\_multiplication], storing the result in 2 BigIntegers and then compute the modulus using the following equality `(highBits*2**255+lowBits)%p=(highBits*2**255)%p+lowBits%p=(highBits*19)%p+lowBits%p` which then gets translated into `modsum(mulmod256(highBits, 19, p), lowBits, p)` and, while mulmod256() can get really expensive this specific instance is really cheap due to 19 being a low number, which causes the loop to run only 5 times (instead of the ~255 iterations on random numbers). The algorithm has some other minor quirks to prevent overflows, but the basic idea is the one presented:
```
private static BigInteger mulmod(BigInteger a, BigInteger b, BigInteger p){
    BigInteger power127 = 2^127;
    BigInteger power128 = power127 * 2;
    BigInteger lowA = a%power128;
    BigInteger lowB = b%power127;
    BigInteger highA = a/power128;
    BigInteger highB = b/power127;
    BigInteger low = (lowA*lowB)%p;
    BigInteger high = (highA*highB)%p;
    BigInteger medium1 = ((lowA/2)*highB)%p;
    BigInteger medium2 = (lowB*highA)%p;
    BigInteger medium = modsum(medium1, medium2, p);
    medium = modsum(medium, medium, p);
    if(lowA%2 == 1){
        medium = modsum(medium, highB, p);
    }
    low = modsum(low, ((medium%power128)*power127)%p, p);
    high = modsum(high, medium/power128, p);
    high = mulmod256(high, 19, p);
    return modsum(high, low, p);
}
```

### Modulus
When SHA512 is computed as part of the signature verification process, a 512-bit value stored in an array of 8 unsigned longs is obtained, which we need to apply a modulus operation to. Our current solution is based on iterating over the binary representation (making sure to interpret the hash result as little-endian) and compute the modulus in 512 steps:
```
private static BigInteger sha512mod(ulong[] num, BigInteger q){
	BigInteger res = 0;
	BigInteger powers = 1;
	for(int i=0; i<8; i++){
		for(int j=0; j<8; j++){
		    for(int k =0; k<8; k++){
				if(((num[i]>>(56+k)) & 1) == 1){
					res = modsum(res, powers, q);
				}
				powers = modsum(powers, powers, q);
		    }
		    num[i] = num[i] << 8;
		}
	}
	return res;
}
```

## Resources
A list of resources that are quite interesting but we still haven't explored in depth:
- [Wikipedia: Multiplication Algorithms](https://en.wikipedia.org/wiki/Multiplication_algorithm)
- [Wikipedia: Arbitrary-precision arithmetic](https://en.wikipedia.org/wiki/Arbitrary-precision_arithmetic)
- [Wikipedia: Karatsuba algorithm](https://en.wikipedia.org/wiki/Karatsuba_algorithm)
- [Wikipedia: SHA2 Pseudocode](https://en.wikipedia.org/wiki/SHA-2#Pseudocode)
- [Book: BigNum Math: Implementing Cryptographic Multiple Precision Arithmetic](http://index-of.co.uk/Hacking-Coleccion/BigNum%20Math%20-%20Implementing%20Cryptographic%20Multiple%20Precision%20Arithmetic.pdf)

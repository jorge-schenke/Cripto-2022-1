#import random
import random
import math

#Basado en: https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/

first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                    31, 37, 41, 43, 47, 53, 59, 61, 67,
                    71, 73, 79, 83, 89, 97, 101, 103,
                    107, 109, 113, 127, 131, 137, 139,
                    149, 151, 157, 163, 167, 173, 179,
                    181, 191, 193, 197, 199, 211, 223,
                    227, 229, 233, 239, 241, 251, 257,
                    263, 269, 271, 277, 281, 283, 293,
                    307, 311, 313, 317, 331, 337, 347, 349]

def isMillerRabinPassed(miller_rabin_candidate):
    '''Run 20 iterations of Rabin Miller Primality test'''
    maxDivisionsByTwo = 0
    evenComponent = miller_rabin_candidate-1
    while evenComponent % 2 == 0:
        evenComponent >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * evenComponent == miller_rabin_candidate-1)
    def trialComposite(round_tester):
        if pow(round_tester, evenComponent, 
                miller_rabin_candidate) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * evenComponent, miller_rabin_candidate) == miller_rabin_candidate-1:
                return False
        return True
    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, miller_rabin_candidate)
        if trialComposite(round_tester):
            return False
    return True

def is_prime( n):
    for prime in first_primes_list:
        if n % prime == 0:
            return False
    if isMillerRabinPassed(n):
        return True

def gcd1(x, y):
    if(y==0):
        return x
    else:
        return gcd1(y,x%y)

class RSAReceiver:
    def __init__(self, bit_len):
        self.bit_len = bit_len
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        self.n = self.p * self.q
        self.d = self.generate_d()
        self.e = self.generate_e()

    def int_to_bytes(self, integer_in):
        length = math.ceil(math.log(integer_in)/math.log(self.bit_len))
        return bytearray(integer_in.to_bytes(length, 'big'))

    def generate_prime(self):
        while True:
            p = random.randint(2**(self.bit_len-1), 2**self.bit_len)
            if is_prime(p):
                return p

    def generate_d(self):
        while True:
            d = random.randint(2**(self.bit_len-1), 2**self.bit_len)
            if gcd1(d, self.n) == 1:
                return d

    def generate_e(self):
        while True:
            e = random.randint(2**(self.bit_len-1), 2**self.bit_len)
            if gcd1(e * self.d, self.n) == 1:
                return e

    def show(self):
        print("p: ", self.p)
        print("q: ", self.q)
        print("n: ", self.n)
        print("d: ", self.d)
        print("e: ", self.e)

    def get_public_key(self):
        e_bytes = self.int_to_bytes(self.e)
        e_len = len(e_bytes)
        e_len_bytes = e_len.to_bytes(4, 'big')
        n_bytes = self.int_to_bytes(self.n)
        n_len = len(n_bytes)
        n_len_bytes = n_len.to_bytes(4, 'big')
        public_key = e_len_bytes + e_bytes + n_len_bytes + n_bytes
        return public_key

    def decrypt(self, ciphertext):
        print(f"Me llegó el mensaje: {ciphertext}")
        cipher_int = int.from_bytes(ciphertext, 'big')
        print(f"El mensaje en int es: {cipher_int}")
        msg_int = pow(cipher_int, self.d, self.n) #Falta exponenciación rápida
        print(f"El mensaje descifrado en int es: {msg_int}")
        msg_bytes = self.int_to_bytes(msg_int)
        print(f"El mensaje descifrado en bytes es: {msg_bytes}")
        msg_string = msg_bytes.decode('utf-8')
        print(f"El mensaje descifrado en string es: {msg_string}")
        return msg_string

class RSASender:
    def __init__(self, public_key):
        self.public_key = public_key
        self.e, self.n = self.get_e_n()
        self.bit_len = math.ceil(math.log(self.n)/math.log(2))

    def int_to_bytes(self, integer_in):
        length = math.ceil(math.log(integer_in)/math.log(self.bit_len))
        return bytearray(integer_in.to_bytes(length, 'big'))

    def show(self):
        print("e: ", self.e)
        print("n: ", self.n)
    
    def get_e_n(self):
        e_len_bytes = self.public_key[0:4]
        e_len = int.from_bytes(e_len_bytes, 'big')
        e_bytes = self.public_key[4:4+e_len]
        e = int.from_bytes(e_bytes, 'big')
        n_len_bytes = self.public_key[4+e_len:8+e_len]
        n_len = int.from_bytes(n_len_bytes, 'big')
        n_bytes = self.public_key[8+e_len:8+e_len+n_len]
        n = int.from_bytes(n_bytes, 'big')
        return e, n
    
    def encrypt(self, msg):
        msg_int = int.from_bytes(msg.encode('utf-8'), 'big')
        print(f"Original en int: {msg_int}")
        cipher_int = pow(msg_int, self.e, self.n) #Falta exponenciación rápida
        cipher_bytes = self.int_to_bytes(cipher_int)
        return cipher_bytes

Rec = RSAReceiver(128)
Rec.show()
print(f"Public key: {Rec.get_public_key()}")

Enc = RSASender(Rec.get_public_key())
Enc.show()
print(f"Encrypting: {'hola'}")
cipher = Enc.encrypt('hola')
print(f"Cipher: {cipher}")
print(f"Decrypting: {cipher}")
print(f"Decrypted: {Rec.decrypt(cipher)}")

import random

# Fichier pour implementer les bases mathématiques pour RSA

def is_prime(n, k=5):  # Fonctions pour vérifier si un nombre est premier
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    elif n % 2 == 0:
        return False
    
    s = 0
    d = n - 1
    while (d % 2 == 0):
        d //= 2
        s = s + 1
    
    for i in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        temoin = False
        for j in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                temoin = True
                break
        if not temoin:
            return False
    return True


def generate_large_prime(bit_length, k=5):  # fonction pour génerer un grand nombre premier
    while True:
        a = pow(2, bit_length - 1)
        b = pow(2, bit_length) - 1
        candidat = random.randint(a, b)
        candidat |= 1
        candidat |= (1 << (bit_length - 1))  # forcer le bit le plus significatif à 1
        if is_prime(candidat, k):
            return candidat


def mod_exp(base, exponent, modulus):  # fonction d'exponentiation modulaire rapide
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base ** 2) % modulus
        exponent //= 2
    return result


def extended_gcd(a, b):
    """Version itérative de l'algorithme d'Euclide étendu pour éviter la récursion"""
    if a == 0:
        return b, 0, 1
    
    # Initialisation
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    
    # Algorithme itératif
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    
    return old_r, old_s, old_t


def mod_inverse(a, m):
    """Calcule l'inverse modulaire de a modulo m"""
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Inverse modulaire impossible : a et m ne sont pas premiers entre eux.")
    return x % m


#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher
import pdb
def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")
    
    ## YOUR CODE HERE

    # Use library function to encrypt the plaintext.
    aes = Cipher("aes-128-gcm")
    iv = urandom(16)
    print type(K)
    ciphertext, tag = aes.quick_gcm_enc(K,iv,plaintext)
  
    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    
    ## YOUR CODE HERE

    aes = Cipher("aes-128-gcm")
   
    
    plain = aes.quick_gcm_dec(K,iv,ciphertext,tag)
    
    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.

#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x == None and y == None)

    if x == None and y == None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = yq - yp * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    # Raise exception, test if points are equal
    
    if ((x0 == x1) and (y0 == y1)):
       raise Exception ('EC Points must not be equal')
    
    # if x1 == x0 then there is no inverse, also check both points are on curve
    if (x0 == x1) or (not is_point_on_curve(a, b, p, x0, y0)) or (not is_point_on_curve(a, b, p, x1, y1)):
       return(None, None)
    
    
    if ((x0==None) and y0 == None) :
       return (x1,y1)
       
    if ((x1==None) and y1 == None) :
       return (x0,y0)

     
    #calculate lam in stages using Bn methods   
    xqminxp = x1.mod_sub(x0,p)
    yqminyp = y1.mod_sub(y0,p)
       
    xqminxpmodinv = xqminxp.mod_inverse(m = p)  
   
    
    # raise Exception(type(xqminxpmodinv))

    lam = xqminxpmodinv.mod_mul(yqminyp,p)
       
    #calculate xr
    
    lamsq = lam.mod_mul(lam,p) 
    lamsqmin = lamsq.mod_sub(x0,p)
    xr = lamsqmin.mod_sub(x1,p)
    
    #calculate yr
    
    xpminxr = x0.mod_sub(xr,p) 
    lamxpxr = lam.mod_mul(xpminxr,p)
    yr = lamxpxr.mod_sub(y0,p)
    
    return (xr, yr)

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = 3 * xp ^ 2 + a * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """  
    #Calculate lam
#    xpsqr = x.mod_mul(x,p)
#    left_oper = Bn(3).mod_mul(xpsqr, p)

#    twoyp = Bn(2).mod_mul(y, p)
#    inv_twoyp = twoyp.mod_inverse(m=p)
#    right_oper = a.mod_mul(inv_twoyp, p)

#   lam = left_oper.mod_add(right_oper)
    
    #Calculate xr
#    lamsqr = lam.mod_mul(lam, p)
#    twoxp = Bn(2).mod_mul(x)
#   xr = lamsqr.mod_minus(twoxp) 
    
    #Calculate yr
#    xp_min_xr = x.mod_sub(xr, p)
#    lam_times_diff = lam.mod_mul(xp_min_xr, p)
#    yr = lam_times_diff.mod_sub(y, p)
#    return xr, yr

    if x==None and y==None:
        return None,None
    
    xsq = x.mod_mul(x,p)
    xsq3 = Bn(3).mod_mul(xsq,p)
    num = xsq3.mod_add(a,p)
    y2 = Bn(2).mod_mul(y,p)
    y2inv = y2.mod_inverse(m = p)
    lam = num.mod_mul(y2inv,p)
    
    xr = lam.mod_mul(lam,p)  
    xr = xr.mod_sub(x,p)
    xr = xr.mod_sub(x,p)

    yr = lam.mod_mul(x.mod_sub(xr,p), p) 
    yr = yr.mod_sub(y,p)

    return (xr, yr)

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of P == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    Q = (None, None)
    P = (x, y)
    xq = Q[0]      # tuples are immutable so we have to split them to do arithmetic on them!
    yq = Q[1] 
    xp = P[0]
    yp = P[1]
    

    for i in range(scalar.num_bits()):
        if scalar.is_bit_set(i):
           
           xq, yq = point_add(a, b, p, xq, yq, xp, yp)
        xp, yp = point_double(a, b, p, xp, yp)
        
    return xq, yq


def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    R0 = (None, None)
    R1 = (x, y)
    x0 = R0[0]      # tuples are immutable so we have to split them to do arithmetic on them!
    y0 = R0[1] 
    x1 = R1[0]
    y1 = R1[1]

#   for i in num_bits(P)-1 to zero:
    for i in reversed(range(0,scalar.num_bits())):
#       if di = 0:
        if not scalar.is_bit_set(i): 
#           R1 = R0 + R1
            x1, y1 = point_add(a, b, p, x0, y0, x1, y1)   
#           R0 = 2R0
            x0, y0 = point_double(a, b, p, x0, y0)
#       else
        else: 
#           R0 = R0 + R1
            x0, y0 = point_add(a, b, p, x0, y0, x1, y1)   
#           R1 = 2 R1
            x1, y1 = point_double(a, b, p, x1, y1)
#   return R0
    return x0, y0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")
    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()
    sig = do_ecdsa_sign(G,priv_sign,digest)
    


    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest() 
    res = do_ecdsa_verify(G, pub_verify, sig, digest)
    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE: 


def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message):
    # first get our public/private key pair
    G, our_priv_dec, our_pub_enc = dh_get_key()
    # generate fresh shared key from the pub key passed and our own private key
    # DH elliptic curve exchange
    # shared point on ec is product of other's public key 
    # and our private key
    # print type(pub) #EcPt
    # print type(our_priv_dec) #Bn
    shared_point = pub.pt_mul(our_priv_dec)
    
    # wikipedia (page for Elliptic Curve Diffie-Hellman) 
    # states that shared secret is the x coordinate of this shared point
    
    x, y = shared_point.get_affine()

    # encrypt using aes_gcm
    
    aes = Cipher("aes-128-gcm")
    iv = urandom(16)
    # check that x is within range of values allowed in aes:
    # we are using 128 bits so we should take low 128 bits of x. 
    
    x = x % Bn.from_hex("100000000000000000000000000000000") # that's 1 with 32 zeros
    plaintext = message.encode("utf8")
    keystring = x.hex().encode("utf8")
    key = unhexlify(keystring)
    
    #print type(key)
    
    #print keystring
    ciphertext, tag = aes.quick_gcm_enc(key,iv,plaintext)
  
    return (iv, ciphertext, tag, our_priv_dec)


def dh_decrypt(pub,priv, ciphertext, iv, tag):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided"""
    
    ## YOUR CODE HERE
    # pub, Bob's public key
    # priv, my private key
    # ciphertext: the ciphertext
    # iv: the initialisation vector
    # tag: the tag created during encipherment
         
    shared_point = pub.pt_mul(priv)
    
    x, y = shared_point.get_affine()
    x = x % Bn.from_hex("100000000000000000000000000000000") # that's 1 with 32 zeros
    keystring = x.hex().encode("utf8")
    print keystring
    key = unhexlify(keystring)

    aes = Cipher("aes-128-gcm")
    plain = aes.quick_gcm_dec(key,iv,ciphertext,tag)
    
    return plain.encode("utf8")

## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 

def test_encrypt():
    assert False

def test_decrypt():
    assert False

def test_fails():
    assert False

#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#           
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different 
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

def time_scalar_mul():
    
    #Test 1: time salar multiplication of double-and-add routine
    
    
    
    pass
    
    

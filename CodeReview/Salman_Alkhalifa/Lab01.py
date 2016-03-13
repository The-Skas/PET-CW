#Lakermance Yoann
#Radinski Plamen

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
import pytest


def encrypt_message(K, message):
    """ Encrypt a message under a key K """
    
    plaintext = message.encode("utf8")
    
    ## YOUR CODE HERE
    iv  = urandom(16)
    aes = Cipher("aes-128-gcm")
    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)
    
    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    ## YOUR CODE HERE
    aes = Cipher("aes-128-gcm")

    plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)

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
    xr, yr = None, None
    
    if x0 == x1 and y0 == y1:
        raise Exception("EC Points must not be equal")
    elif x0 == None and y0 == None:
        return (x1,y1)
    elif x1 == None and y1 == None:
        return (x0,y0)
    elif x0.mod_sub(x1,p) == 0:
        return (None, None)
    else:    
        lam = (y1.mod_sub(y0,p)).mod_mul((x1 - x0).mod_inverse(p),p)
        xr  = ((lam.mod_pow(2,p)).mod_sub(x0,p)).mod_sub(x1,p)
        yr  = (lam.mod_mul(x0.mod_sub(xr,p),p)).mod_sub(y0,p) 
        
    
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

    # ADD YOUR CODE BELOW
    xr, yr = None, None
    if x == None and y == None:
        return (x,y)
    else:
        lam = ((Bn(3).mod_mul(x.mod_pow(2,p),p)).mod_add(a,p)).mod_mul((Bn(2).mod_mul(y,p)).mod_inverse(p),p)
        xr  = (lam.mod_pow(2,p)).mod_sub(Bn(2).mod_mul(x,p),p)
        yr  = (lam.mod_mul(x.mod_sub(xr,p),p)).mod_sub(y,p)

    return xr, yr

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
    R = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        pass ## ADD YOUR CODE HERE
        
        if scalar.is_bit_set(i):
            Q = point_add(a,b,p,Q[0],Q[1],P[0],P[1])
            
        ## Doing a point addition just to negate the side channel.
        ## R is never used, just here to introduce the right delay when the bit is not set. 
        else:
            R = point_add(a,b,p,Q[0],Q[1],P[0],P[1])
            
        P = point_double(a,b,p,P[0],P[1])
    
    return Q

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

    for i in reversed(range(0,scalar.num_bits())):
        pass ## ADD YOUR CODE HERE
        
        if not scalar.is_bit_set(i):
            R1 = point_add(a,b,p,R1[0],R1[1],R0[0],R0[1])
            R0 = point_double(a,b,p,R0[0],R0[1])
        else:
            R0 = point_add(a,b,p,R1[0],R1[1],R0[0],R0[1])
            R1 = point_double(a,b,p,R1[0],R1[1])

    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup, EcPt
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
    sig = do_ecdsa_sign(G, priv_sign, digest)

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
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message.
    """ 
    ## YOUR CODE HERE
    pass
    ## Generate a fresh DH key
    G, priv_key, pub_key = dh_get_key()
    
    ## Retrieve the EC point from the binary

    pub = EcPt.from_binary(pub,G)
    
    ## Generate the public binary for the fresh key
    pub_key_string = pub_key.export()
    
    ## Derive a fresh shared key
    shared_key = pub.pt_mul(priv_key)
    shared_key = (shared_key.export())
    shared_key = sha256(shared_key).digest()
    
    ## Encrypt and sign the message
    plaintext = message.encode("utf8")
    
    iv  = urandom(32)
    aes = Cipher("aes-256-gcm")
    
    ciphertext, tag = aes.quick_gcm_enc(shared_key, iv, plaintext)
    
    return (iv, ciphertext, tag, pub_key_string)

def dh_decrypt(priv, ciphertext):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided"""
    
    ## YOUR CODE HERE
    pass
    
    G = EcGroup()
    iv, ciphertext, tag, pub_string = ciphertext
    
    pub = EcPt.from_binary(pub_string,G)
        
    ## Derive the fresh shared key
 
    shared_key = pub.pt_mul(priv)
    shared_key = (shared_key.export())
    shared_key = sha256(shared_key).digest()
    
    ## Encrypt and sign the message
 
    aes = Cipher("aes-256-gcm")
    
    plaintext = aes.quick_gcm_dec(shared_key, iv, ciphertext, tag)
    
    return plaintext.decode("utf8")

## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 
@pytest.mark.task5
def test_gen():
    
    G,priv,pub = dh_get_key()
    
    assert G.check_point(pub)
@pytest.mark.task5
def test_encrypt():
   
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    pub_enc_string = pub_enc.export()    
   
    message = u"Hello World!"
    iv, ciphertext, tag, pub_string = dh_encrypt(pub_enc_string, message)
    
    pub = EcPt.from_binary(pub_string,G)

    assert len(iv) == 32
    assert len(ciphertext) == len(message)
    assert len(tag) == 16
    assert G.check_point(pub)

@pytest.mark.task5    
def test_encrypt_fail_point():
    from pytest import raises
    
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    pub_enc_string = pub_enc.export()    
   
    message = u"Hello World!"
    
    with raises(Exception) as excinfo:
        
        random_pub_point_string = urandom(len(pub_enc_string))
        iv, ciphertext, tag, pub_string = dh_encrypt(random_pub_point_string, message)
   
    assert 'EC exception' in str(excinfo.value)

@pytest.mark.task5
def test_decrypt():

    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    pub_enc_string = pub_enc.export()
    
    message = u"Hello World!"
    iv, ciphertext, tag, pub_string = dh_encrypt(pub_enc_string, message)

    pub = EcPt.from_binary(pub_string,G)

    assert len(iv) == 32
    assert len(ciphertext) == len(message)
    assert len(tag) == 16
    assert G.check_point(pub)
    
    ciphertext = (iv, ciphertext, tag, pub_string)
    m = dh_decrypt(priv_dec, ciphertext)
    
    assert m == message
    
@pytest.mark.task5
def test_fails():
    from pytest import raises
    
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    pub_enc_string = pub_enc.export()
    
    message = u"Hello World!"
    iv, ciphertext, tag, pub_string = dh_encrypt(pub_enc_string, message)
    
    with raises(Exception) as excinfo:
        dh_decrypt(priv_dec, (iv, urandom(len(ciphertext)), tag, pub_string))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_dec, (iv, ciphertext, urandom(len(tag)), pub_string))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_dec, (urandom(len(iv)), ciphertext, tag, pub_string))
    assert 'decryption failed' in str(excinfo.value)
    
    with raises(Exception) as excinfo:
        random_pub_point_string = urandom(len(pub_string))
        dh_decrypt(priv_dec, (iv, ciphertext, tag, random_pub_point_string))
    assert 'EC exception' in str(excinfo.value)

    with raises(Exception) as excinfo:
        random_priv_point = G.order().random()
        dh_decrypt(random_priv_point, (iv, ciphertext, tag, pub_string))
    assert 'decryption failed' in str(excinfo.value)          

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
    pass
    
    import time
    
    # Initialization
    G = EcGroup(713)
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()
    
    print "Number of bits of the order of G: "+str(G.order().num_bits())
    
   
    rs = []
    rb = 0
    
    #Loop over 100 random secret key and timing
    
    for i in range(1, 100):
        r = G.order().random()
        rb = 0
        for j in range(r.num_bits()):
            if r.is_bit_set(j):
                rb = rb+1
        
        
        t00 = time.clock()
        point_scalar_multiplication_double_and_add(a, b, p, gx0, gy0, r)
        t01 = time.clock()
        
     
        t10 = time.clock()
        point_scalar_multiplication_montgomerry_ladder(a, b, p, gx0, gy0, r)
        t11 = time.clock()
       
        
        rs.append((rb,r,t01-t00,t11-t10))
        
        
    def getKey(item):
        return item[0] 
     
    rs = sorted(rs, key=getKey)
    
                
    # Print the report
    # Need to run this in cmd line : python -c 'import Lab01Code; Lab01Code.time_scalar_mul()'
    print "Number of bit set to 1 | Double and add | Montgommery ladder"
    for r in rs:
        print str(r[0])+" | "+str(r[2])+" | "+str(r[3])
       
    


#Test to understand the elliptic curve group notations
import petlib
from os import urandom
from petlib.cipher import Cipher
from petlib.bn import Bn

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from binascii import unhexlify





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
    print type(pub) #EcPt
    print type(our_priv_dec) #Bn
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
        
# simple test


## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 

def test_encrypt():
    G, priv_dec, pub_enc = dh_get_key()
    iv, ciphertext, tag, priv = dh_encrypt(pub_enc,"Hello World")
    assert True
    return iv, ciphertext, tag, priv
    
def test_decrypt():
    plain =  dh_decrypt(pub_enc, priv, ciphertext, iv, tag)
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

import time
from Lab01Code import point_scalar_multiplication_double_and_add
from Lab01Code import point_scalar_multiplication_montgomerry_ladder
from Lab01Code import point_add
from Lab01Code import point_double

def time_scalar_mul():

    # take code from Lab01Tests.py to initialise variales
    
    G = EcGroup(713) # NIST curve
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()

    timed_run(a,b,p,gx0,gy0,Bn(1))
    timed_run(a,b,p,gx0,gy0,Bn(15))
    timed_run(a,b,p,gx0,gy0,Bn(16))
    timed_run(a,b,p,gx0,gy0,Bn(31))
    timed_run(a,b,p,gx0,gy0,Bn(32))
    timed_run(a,b,p,gx0,gy0,Bn(63))


def timed_run(a, b, p, gx0, gy0, r): 
    testmodule = 'enhanced'
    start = time.clock()
    for i in range(100):
        if testmodule == 'enhanced' :
            point_scalar_multiplication_montgomerry_ladder_const_time(a, b, p, gx0, gy0, r)
        else:   
            point_scalar_multiplication_montgomerry_ladder(a, b, p, gx0, gy0, r)

    end = time.clock()
    #print "start run 100x  scalar is ",r, "time ", start
    #print "end   run 100x  scalar is ",r, "time ", end
    print "duration  100x  scalar is ",r, "time ", end-start
    

#####################################################
# The code above (timed_run) shows that even the montgommerry-ladder approach
# leaks information: the time taken is independent of the number of 1s and 0s 
# in the problem but totally dependent on the total number of bits
# A way of avoiding this (at the cost of extra time) is to force the 
# implementation to run over the same number of cycles regardless of the 
# size of the scalar. 
#
# A revised montgommerry-ladder routine could be like this:

def point_scalar_multiplication_montgomerry_ladder_const_time(a, b, p, x, y, scalar):
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
    maxsize = 512
    if scalar.num_bits() > maxsize:
       raise Exception ("Scalar Too Big!")

#   for i in num_bits(P)-1 to zero:
    for i in reversed(range(0,maxsize)):
#       if di = 0:
        if (not scalar.is_bit_set(i)) or i>scalar.num_bits(): 
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


time_scalar_mul()  


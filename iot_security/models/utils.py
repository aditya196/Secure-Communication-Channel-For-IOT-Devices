import string
import random

def rand_pass(size):
    generate_pass = ''.join([random.SystemRandom().choice( string.ascii_uppercase +
                                            string.digits)  
                                            for n in range(size)])  
                             
    return generate_pass
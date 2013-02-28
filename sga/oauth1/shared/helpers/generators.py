import os
import random
import time


def generate_nonce(length=8):
    return os.urandom(length).encode('hex')


def generate_timestamp(length=8):
    return int(time.time())


def generate_verifier(length=8):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def make_random(length=35):
    return os.urandom(length).encode('hex')

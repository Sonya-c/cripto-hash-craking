import pandas as pd
import timeit
import multiprocessing

from time import time

from typing import List, Tuple, Dict 

from Crypto.Hash import SHA3_512
from Crypto.Protocol.KDF import PBKDF2

import multiprocessing
from os import getpid 
import numpy as np


def H(data: str, salt: str = None, pepper: int = None) -> str:
  """Hash function using SHA3_512

  Args:
      data (str)
      salt (str, optional): Hex string. Defaults to None.
      pepper (int, optional): Defaults to None.

  Returns:
      str: hashed data
  """
  
  h = SHA3_512.new(data=bytes(data, "utf-8"))

  if pepper != None: 
    h.update(pepper.to_bytes(16,'big'))
  
  if salt != None: 
    h.update(bytes.fromhex(salt))

  return h.hexdigest()


def timer(f):
  def wrap(*args, **kwargs):
    t1 = time()
    result = f(*args, **kwargs)
    t2 = time()
    print(f'Function {f.__name__!r} executed in {(t2-t1):.4f}s')
    return result
  return wrap


# Definición de la clase
class ParallelAtack:

    @staticmethod
    def _worker(
        id: str,
        plain_passwords: List[str],
        hash: str,
        salt: str,
        found_event: multiprocessing.Event) -> None:
        
        print(f"Start process {id} {[{getpid()}]}\n")

        for pwd in plain_passwords:
            for pepper in range(2**16):
                if H(pwd, salt, pepper) == hash:
                    print("Found ", pwd)
                    found_event.set()


    @timer
    @staticmethod
    def find(
        plain_passwords: List[str],
        hash: str,
        salt: str) -> None:

        num_processes = multiprocessing.cpu_count()
        chunks = np.array_split(plain_passwords, num_processes)

        print(f"num of process = {num_processes}")

        found_event = multiprocessing.Event()

        pool = [
            multiprocessing.Process(
                target=ParallelAtack._worker,
                args=(i, chunk, hash, salt, found_event)
            )
            for i, chunk in enumerate(chunks)
        ]

        print("Starting process")
        for p in pool: p.start()
        
        # block util condition met
        found_event.wait()

        print("Terminate")
        for p in pool: p.terminate()

        print("Join process")
        for p in pool: p.join()


if __name__ == "__main__":
    plain_passwords = []
    with open("./data/rockyou.txt", "r", encoding="ISO-8859-1") as rockyou:
        for plain in rockyou:
            plain = plain.strip()
            plain_passwords.append(plain)
            
    print(f"Total passwords = {len(plain_passwords)}")

    filename = 'password_database_v3.csv'
    USERNAMES = ['sonyac', 'awperez', 'mhiguita', 'cleonard'] 

    db_v3 = pd.read_csv(f"data/{filename}")
    db_v3 = db_v3[db_v3['username'].isin(USERNAMES)]

    _, salt, _ = db_v3.iloc[1]
    
    multiprocessing.set_start_method('spawn')  # Set start method to 'spawn'
    ParallelAtack.find(plain_passwords, H('morelove3', salt, 123), salt)
    # password = input("Hash password")
    # salt = input("Salt")

    # ParallelAtack.find(plain_passwords, password, salt)
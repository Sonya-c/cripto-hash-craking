import sys
import multiprocessing
from os import getpid 

from time import time
from Crypto.Hash import SHA3_512

global plain_passwords
plain_passwords = []

with open("./data/rockyou.txt", "r", encoding="ISO-8859-1") as rockyou:
  for plain in rockyou:
    plain = plain.strip()
    plain_passwords.append(plain)

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
    hash: str,
    salt: str,
    found_event: multiprocessing.Event) -> None:
    
    print(f"Start process {id} {[{getpid()}]}\n", flush=True)

    chunk_size = len(plain_passwords) // multiprocessing.cpu_count()
    start_index = id * chunk_size
    end_index = (id + 1) * chunk_size if id < multiprocessing.cpu_count() - 1 else len(plain_passwords)
    
    # print(f"Process {id} {[{getpid()}]} | plan passwords head = {plain_passwords[start_index:start_index +10]}\n", flush=True)
    
    for pwd in plain_passwords[start_index:end_index]:
        # if id == 3: print(pwd, flush=True)
        
        for pepper in range(2**16):
            if H(pwd, salt, pepper) == hash:
                print(f"Finishing process {id} {[{getpid()}]} | Found {pwd} \n", flush=True)
                found_event.set()
                return pwd 
            
    print(f"Finishing process {id} {[{getpid()}]} | not found \n", flush=True)

  @timer
  @staticmethod
  def find(
    hash: str,
    salt: str) -> None:

    num_processes = multiprocessing.cpu_count()

    print(f"num of process = {num_processes}")

    found_event = multiprocessing.Event()

    pool = [
        multiprocessing.Process(
            target=ParallelAtack._worker,
            args=(i, hash, salt, found_event)
        )
        for i in range(num_processes)
    ]

    print("Starting process")
    for p in pool: p.start()
    
    # block until condition met
    found_event.wait()

    print("Terminate")
    for p in pool: p.terminate()

    print("Join process")
    for p in pool: p.join()


if __name__ == "__main__":
	print(f"Total passwords = {len(plain_passwords)}")
  
	password, salt = sys.argv[1:]

	print(password, salt)
	
	multiprocessing.set_start_method('spawn')  # Set start method to 'spawn'
	ParallelAtack.find(password, salt)
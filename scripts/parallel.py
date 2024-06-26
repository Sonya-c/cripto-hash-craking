
import sys
from os import getpid 
import multiprocessing as mp

from time import time
from Crypto.Hash import SHA3_512

global plain_passwords
plain_passwords = []

# Leer contraseñas en texto plano
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


# Decorador para el calculo de tiempo
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
    processs_id: int,
    hash: str,
    salt: str,
    found_event: mp.Event) -> None:
    
    print(f"Start process {processs_id} {[{getpid()}]}\n", flush=True)

    chunk_size = len(plain_passwords) // mp.cpu_count()
    start_index = processs_id * chunk_size
    end_index = (processs_id + 1) * chunk_size if processs_id < mp.cpu_count() - 1 else len(plain_passwords)
    
    # print(f"Process {processs_id} {[{getpid()}]} | plan passwords head = {plain_passwords[start_index:start_index +10]}\n", flush=True)
    
    for pwd in plain_passwords[start_index:end_index]:
      # if processs_id == 3: print(pwd, flush=True)
      
      for pepper in range(2**16):
        if H(pwd, salt, pepper) == hash:
          print(f"Finishing process {processs_id} {[{getpid()}]} | Found {pwd} \n", flush=True)
          found_event.set()
          return pwd 
            
    print(f"Finishing process {processs_id} {[{getpid()}]} | not found \n", flush=True)

  @timer
  @staticmethod
  def find(
    hash: str,
    salt: str) -> None:

    num_processes = mp.cpu_count()

    print(f"num of process = {num_processes}")

    found_event = mp.Event()

    pool = [
      mp.Process(
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
	
	mp.set_start_method('spawn')  # Set start method to 'spawn'
	ParallelAtack.find(password, salt)

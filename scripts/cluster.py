
import sys
import multiprocessing
from os import getpid 

from time import time
from Crypto.Hash import SHA3_512


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
    process_id: str,
    plain_passwords,
    hash: str,
    salt: str,
    found_event: multiprocessing.Event) -> None:
    
    print(f"Start process {process_id} {[{getpid()}]}\n", flush=True)

    chunk_size = len(plain_passwords) // multiprocessing.cpu_count()
    start_index = process_id * chunk_size
    end_index = (process_id + 1) * chunk_size if process_id < multiprocessing.cpu_count() - 1 else len(plain_passwords)
    
    for pwd in plain_passwords[start_index:end_index]:
      
      for pepper in range(2**16):
        if H(pwd, salt, pepper) == hash:
          print(f"Finishing process {process_id} {[{getpid()}]} | Found {pwd} \n", flush=True)
          found_event.set()
          return pwd 
            
    print(f"Finishing process {process_id} {[{getpid()}]} | not found \n", flush=True)

  @timer
  @staticmethod
  def find(
    plain_passwords,
    hash: str,
    salt: str) -> None:

    num_processes = multiprocessing.cpu_count()

    print(f"num of process = {num_processes}")

    found_event = multiprocessing.Event()

    pool = [
      multiprocessing.Process(
        target=ParallelAtack._worker,
        args=(i, plain_passwords,hash, salt, found_event)
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

  plain_passwords = []

  cluster_id, cluster_size, password, salt = sys.argv[1:]

  cluster_id = int(cluster_id)
  cluster_size = int(cluster_size)

  with open("./data/rockyou.txt", "r", encoding="ISO-8859-1") as rockyou:
    for plain in rockyou:
      plain = plain.strip()
      plain_passwords.append(plain)

  chunk_size = len(plain_passwords) // cluster_size
  start_index = cluster_id * chunk_size
  end_index = (cluster_id + 1) * chunk_size if cluster_id < cluster_size - 1 else len(plain_passwords)

  plain_passwords = plain_passwords[start_index:end_index]
  print(f"Total passwords = {len(plain_passwords)}")

  ParallelAtack.find(plain_passwords, password, salt)

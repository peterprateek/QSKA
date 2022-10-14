# -*- coding: utf-8 -*-

!pip install "qiskit[visualization]" --user

!pip install qiskit-optimization

!pip install qiskit
#!pip3 install qiskit

import qiskit
qiskit.__version__      # checks the version

!pip install Crypto
!pip install pycrypto
!pip install bitstring

from bitstring import BitArray
import random
import string
import argparse
import select
import socket
import sys
import signal
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import hmac

# import all necessary objects and methods for quantum circuits
from qiskit import QuantumRegister, ClassicalRegister, QuantumCircuit, execute, Aer

def CSregistration(identity):

  password = input("CS - Input your password for registration (Enter 8 bits either (0/1)): ")  # CS enters 8 bits password and press enter
  print("CS - Your entered registration password is: ", password)

  CS_pairs = [password[i:i+2] for i in range(0, len(password), 2)]  # For every two bits of CS password, CS uses SDC to transfer password to UC

  
  l = []
  for pair in CS_pairs:

      # create a quantum curcuit with two qubits: CS's and UC's qubits.
      # both are initially set to |0>.
      q = QuantumRegister(2,"q") # quantum register with 2 qubits
      c = ClassicalRegister(2,"c") # classical register with 2 bits
      qc = QuantumCircuit(q,c) # quantum circuit with quantum and classical registers

      # apply h-gate (Hadamard) to the CS's qubit
      qc.h(q[1])

      # apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])

      # they are separated from each other now

      # if a is 1, then apply z-gate to CS's qubit
      if pair[0]=='1': 
          qc.z(q[1])
      
      # if b is 1, then apply x-gate (NOT) to CS's qubit
      if pair[1]=='1': 
          qc.x(q[1])
      
      # CS sends her qubit to UC
      qc.barrier()
      
      #  apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])
      
      # apply h-gate (Hadamard) to the CS's qubit
      qc.h(q[1])
      
      # measure both qubits
      qc.barrier()
      qc.measure(q,c)
      
      # draw the circuit in Qiskit's reading order
      display(qc.draw(output='mpl',reverse_bits=True))
      
      # compare the results with pair (a,b)
      job = execute(qc,Aer.get_backend('qasm_simulator'),shots=100)
      counts = job.result().get_counts(qc)
      print(pair,"-->",counts)
      for s in counts:
      
       l.extend(s)
       tpassword = (''.join(l))
      
    # Merging the CS's transferred password at UC end


    #  Storing CS identity and corresponding password in UC database for CS.
    # Printing that your password has been successfully transfered and stored in UC database.
  with open('UCS_database.txt', 'a') as filehandle:
    filehandle.write(f'{identity}\t')
    filehandle.write(f'{tpassword}\n')
    print("The registration password stored successfully in UC database for CS")
    print("Successfully CS registered")   

    # This concludes that the CS has successfully transffered his password to UC using SDC. 


def EVregistration(identity):

  password1 = input("EV - Input your password for registration (Enter 8 bits either (0/1)) : ")  # EV enters 8 bits password and press enter
  print("EV - Your Entered password for registration is: ", password1)

  EV_pairs = [password1[i:i+2] for i in range(0, len(password1), 2)]  # For every two bits of EV password, EV uses SDC to transfer password to UC

  #all_pairs = ['00','01','10','11']
  l = []
  for pair in EV_pairs:

      # create a quantum curcuit with two qubits: CS's and UC's qubits.
      # both are initially set to |0>.
      q = QuantumRegister(2,"q") # quantum register with 2 qubits
      c = ClassicalRegister(2,"c") # classical register with 2 bits
      qc = QuantumCircuit(q,c) # quantum circuit with quantum and classical registers

      # apply h-gate (Hadamard) to the CS's qubit
      qc.h(q[1])

      # apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])

      # they are separated from each other now

      # if a is 1, then apply z-gate to CS's qubit
      if pair[0]=='1': 
          qc.z(q[1])
      
      # if b is 1, then apply x-gate (NOT) to CS's qubit
      if pair[1]=='1': 
          qc.x(q[1])
      
      # CS sends her qubit to UC
      qc.barrier()
      
      #  apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])
      
      # apply h-gate (Hadamard) to the CS's qubit
      qc.h(q[1])
      
      # measure both qubits
      qc.barrier()
      qc.measure(q,c)
      
      # draw the circuit in Qiskit's reading order
      display(qc.draw(output='mpl',reverse_bits=True))
      
      # compare the results with pair (a,b)
      job = execute(qc,Aer.get_backend('qasm_simulator'),shots=100)
      counts = job.result().get_counts(qc)
      print(pair,"-->",counts)
      for s in counts:
       
       l.extend(s)
       tpassword1 = (''.join(l))
     
      # Merging the EV's transferred password at UC end
     

    # Storing EV identity and corresponding password in UC database for EV.
    # Printing that your password has been successfully transfered and stored in UC database. 
  with open('UEV_database.txt', 'a') as filehandle:
    filehandle.write(f'{identity}\t')
    filehandle.write(f'{tpassword1}\n')
    print("The registration Password stored successfully in UC database for EV")
    print("Successfully EV registered")   

 # This concludes that the EV has successfully transfered his password to UC using SDC.

def phase4(sessionkey, pidentity):
    
    ckey = hashlib.sha256(sessionkey.encode('utf8')).digest()

    # generate a random number r, size of 8 bytes 
    r = Random.new().read(8)

    p = Random.new().read(16)

    length = len(identity)
    
    a = identity
    b = r
    concat = a+b
   

    concat = str(concat)

    while len(bytes(concat, encoding='utf-8')) % 16 != 0:
      concat = concat + random.choice(string.ascii_letters)



    # Encrypting the result of concat with the password of the electric vehicle thereby generating pseudo-identity
    iiita = AES.new(ckey, AES.MODE_CBC, p)
    pseudoidentity = iiita.encrypt(concat)  
    
    #  Generating a random location identity (LID), size of 4 bytes
    lid = Random.new().read(4)
    concat1 = str(lid)

    while len(bytes(concat1, encoding='utf-8')) % 16 != 0:
      concat1 = concat1 + random.choice(string.ascii_letters)
    
    # Encrypting the location identity with session key of the electric vehicle

    iiita1 = AES.new(ckey, AES.MODE_CBC, p)
    cipherencvalue = iiita1.encrypt(concat1) 
    
    # Generate timestamp, size of 4 bytes
    timestamp = Random.new().read(4)
    
    # Concatenating step#8 (pseudo-identity) and step#8.2 and step#9 (Timestamp (TS)) thereby generating z
    
    z = cipherencvalue + pseudoidentity + timestamp
       
    
    # Now calculating M (do HMAC with session key and Z)
    M = hmac.new(z, ckey, hashlib.sha256).digest()
   

    # Send the Charging request to Charging station
    crequest = M + cipherencvalue + pseudoidentity + timestamp
    
    return crequest
    
    
    #-------------------------------------------------------------------------------------------------------------
   # -------------------------------------------------------------------------------------------------------------
    # Now Charging station will authenticate the charging request received from vehicle by authenticating M by looking to 
    # each session key corresponding to received pseudo-identity in its database. It computes HMAC M' and then compares 
    # M with M'.
    
    
    
def msgverification(pidentity, crequest):
    #  CS reads its database and corresponding to pseudo-identity, extract session key x[3] x[4]
  with open('CS_EV_Sessionkey_database.txt', 'r') as filehandle:
    for a in filehandle:
      x = a.strip().split("\t")
      
      print(type(x[0]))
      if str(pidentity) == x[0] :
        print("EV pseudo identity matches")
        tpassword3 = x[1] 
      else :
        print("EV pseudo identity not found")
        return 1;

    ckey = hashlib.sha256(tpassword3).digest()
    
    # split the crequest to M(HMAC(sessionkey,z)), cipherencvalue, pseudoidentity, timestamp
    length = len(crequest)
    timestamp = crequest[length - 4:length]
    pseudoidentity = crequest[length - 36:length - 4]
    cipherencvalue = crequest[32:length - 36]
    M = crequest[0:32]  
    zz = cipherencvalue + pseudoidentity + timestamp #

    
    # do hmac (M' of the QSKA paper is represented here as MM)
    MM = hmac.new(zz, ckey, hashlib.sha256).digest()

    # verify anthentication using HMAC, if doesn't match, print error message and exit
    if hmac.compare_digest(M, MM) is False:
        print("HMAC doesn't match! crequest is illegal!!!, reporting pseudoidentity to UC")
    else:
        print("HMAC match! crequest is legal!!!, Processing crequest")
        exit(0)
        
        # Charging station now look for Location id LID by decrypting cipherencvalue

    # decrypt
    p = Random.new().read(16)

    iiita3 = AES.new(ckey, AES.MODE_CBC, p)
    locationid = iiita3.decrypt(cipherencvalue)
    ptext = locationid #.decode('utf8')
    
    return ptext

def phase3(identity2, password4):

  dkey = hashlib.sha256(str.encode(password4)).digest()

  # generate a random number r, size of 8 bytes 
  r = Random.new().read(8)
    
  identity2 = str(identity2, 'ISO-8859-1') 
  length = len(identity2)
    
  
  a = identity2
  b = str(r)
  concat = a + b

  print("Pseudoidentity generation in process")

  concat = str(concat)

  while len(bytes(concat, encoding='utf-8')) % 16 != 0:
      concat = concat + random.choice(string.ascii_letters)
 
  p = Random.new().read(16)  # to be used in AES
    # Encrypting the concat with the password of the electric vehicle thereby generating pseudo-identity
  iiita = AES.new(dkey, AES.MODE_CBC, p)
  pseudoidentity = iiita.encrypt(concat)  
  print("Pseudoidentity for EV generated")

     # Generate a timestamp
  timestamp = Random.new().read(4)
  

  UCACKVreq = pseudoidentity + timestamp
    
  #UCACKVreq = str(UCACKVreq)

  print("EV receives back UCACKVreq")
  print("EV starts decrypting UCAKVreq to match its identity")
  
  length = len(UCACKVreq)
  timestamp = UCACKVreq[length - 4:length]
  pidentity = UCACKVreq[0:length-4]  
  
  
  pidentity1 = pidentity
  

  
  # Decrypt the ppseudoidentity
  iiita4 = AES.new(dkey, AES.MODE_CBC, p)
  encryptedid = iiita4.decrypt(pidentity1)
  length = len(encryptedid)
  extract = encryptedid[0: length-32]
  
  wert = extract
 
  if wert == bytes(identity2,'utf-8'):
    print("Successful Mutual Authentication")
    print("Session key generation corresponding to Pseudoidentity begins")
    sessionkey = input("EV - Input your session key (Enter 8 bits either (0/1)): ")  # EV enters new 8 bits session key and press enter
    print("Your entered session key is: ", sessionkey)
      

    Skey_pairs = [sessionkey[i:i+2] for i in range(0, len(sessionkey), 2)] # For every two bits of EV password,EV uses SDC to transfer password to CS

    l = []
    for pair in Skey_pairs:

        # create a quantum circuit with two qubits: EV's and UC's qubits.
        # both are initially set to |0>.
        q = QuantumRegister(2,"q") # quantum register with 2 qubits
        c = ClassicalRegister(2,"c") # classical register with 2 bits
        qc = QuantumCircuit(q,c) # quantum circuit with quantum and classical registers

        # apply h-gate (Hadamard) to the CS's qubit
        qc.h(q[1])
 
        # apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
        qc.cx(q[1],q[0])

        # they are separated from each other now

        # if a is 1, then apply z-gate to EV's qubit
        if pair[0]=='1': 
          qc.z(q[1])
    
        # if b is 1, then apply x-gate (NOT) to EV's qubit
        if pair[1]=='1': 
          qc.x(q[1])
    
        # EV sends her qubit to UC
        qc.barrier()
    
        #  apply cx-gate as CNOT(EV's-qubit,UC's-qubit)
        qc.cx(q[1],q[0])
    
        # apply h-gate (Hadamard) to the EV's qubit
        qc.h(q[1])
    
        # measure both qubits
        qc.barrier()
        qc.measure(q,c)
    
        # draw the circuit in Qiskit's reading order
        display(qc.draw(output='mpl',reverse_bits=True))
    
    # compare the results with pair (a,b)
        job = execute(qc,Aer.get_backend('qasm_simulator'),shots=100)
        counts = job.result().get_counts(qc)
        print(pair,"-->",counts)
        for s in counts:
         
          l.extend(s)
          tsessionkey = (''.join(l))
          
      # Merging the EV's transferred session key at CS end

       
    #  Storing  received sesion key  in local variable.
    # Printing that your session key has been successfully received.
    with open('CS_EV_Sessionkey_database.txt', 'a') as filehandle:
      filehandle.write(f'{pidentity}\t')
      filehandle.write(f'{tsessionkey}\n')
      print("The sessionkey successfully transferred and stored in CS database for EV")
       # open the CS database file corresponding to EV.
      #  Storing EV ppseudoidentity and corresponding sessionkey in CS database for EV.
      # Printing that your sessionkey has been successfully transfered and stored in CS database.
    with open('EV_database.txt', 'w') as filehandle:
      filehandle.write(f'{identity2}\t')
      filehandle.write(f'{password4}\t')
      filehandle.write(f'{pidentity}\t')
      filehandle.write(f'{sessionkey}\n')

# This concludes that the EV has successfully transfered his session key to UC using SDC.

def EVPreauthentication(identity2, password4):

  EV1_pairs = [password4[i:i+2] for i in range(0, len(password4), 2)] # For every two bits of EV password, EV uses SDC to transfer password to UC

  l = []
  for pair in EV1_pairs:

      # create a quantum circuit with two qubits: EV's and UC's qubits.
      # both are initially set to |0>.
      q = QuantumRegister(2,"q") # quantum register with 2 qubits
      c = ClassicalRegister(2,"c") # classical register with 2 bits
      qc = QuantumCircuit(q,c) # quantum circuit with quantum and classical registers

      # apply h-gate (Hadamard) to the CS's qubit
      qc.h(q[1])

      # apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])

      # they are separated from each other now

      # if a is 1, then apply z-gate to EV's qubit
      if pair[0]=='1': 
          qc.z(q[1])
      
      # if b is 1, then apply x-gate (NOT) to EV's qubit
      if pair[1]=='1': 
          qc.x(q[1])
      
      # EV sends her qubit to UC
      qc.barrier()
      
      #  apply cx-gate as CNOT(EV's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])
      
      # apply h-gate (Hadamard) to the EV's qubit
      qc.h(q[1])
      
      # measure both qubits
      qc.barrier()
      qc.measure(q,c)
      
      # draw the circuit in Qiskit's reading order
      display(qc.draw(output='mpl',reverse_bits=True))
      
      # compare the results with pair (a,b)
      job = execute(qc,Aer.get_backend('qasm_simulator'),shots=100)
      counts = job.result().get_counts(qc)
      print(pair,"-->",counts)
      for s in counts:
       
        l.extend(s)
        tpassword4 = (''.join(l))
      # Merging the EV's transferred password at UC end
      

       #  Storing  received password in in local variable.
        # Printing that your password has been successfully received and the matching has been started with the stored password available in UC database.

        # open the UC database file corresponding to EV.
        #search for corresponding identity in saved list and extract the corresponding password for that identity.
      
  with open('UEV_database.txt', 'r') as filehandle:

    for a in filehandle:
      # a = filehandle.read()
      x = a.strip().split("\t")
      #print(x, str(identity2, 'utf-8'))
      #print(identity2, f'{identity2}')
      print(identity2, type(x[0]))
      #print(str(identity2, 'utf-8'), x[0])
      if str(identity2, 'ISO-8859-1') == x[0] :
        #if identity2.decode() == x[0] :                           
        print("EV identity matches")
        if tpassword4 == x[1] :
          print("EV password matches: legal EV")
          return 0
        else :
          print("EV password not match, Authentication fails!")
          return 1
      else:
        continue
        
  print("EV identity not found, Authentication fails!")
  return 1
        

        # match the received password with the extracted corresponding password
        #  If match is successful, print legal EV
 # This concludes that the EV has been successfully authenticated using SDC.

def CSPreauthentication(identity):

  password3 = input("CS - Input your password for pre-authentication (Enter 8 bits either (0/1)): ")  # CS enters 8 bits password which is used at the time of registration and press enter
  print("CS's entered password for pre-authentication is: ", password3)
  
  CS1_pairs = [password3[i:i+2] for i in range(0, len(password3), 2)] # For every two bits of CS password, CS uses SDC to transfer password to UC

  l = []
  for pair in CS1_pairs:

      # create a quantum circuit with two qubits: CS's and UC's qubits.
      # both are initially set to |0>.
      q = QuantumRegister(2,"q") # quantum register with 2 qubits
      c = ClassicalRegister(2,"c") # classical register with 2 bits
      qc = QuantumCircuit(q,c) # quantum circuit with quantum and classical registers

      # apply h-gate (Hadamard) to the CS's qubit
      qc.h(q[1])

      # apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])

      # they are separated from each other now

      # if a is 1, then apply z-gate to CS's qubit
      if pair[0]=='1': 
          qc.z(q[1])
      
      # if b is 1, then apply x-gate (NOT) to CS's qubit
      if pair[1]=='1': 
          qc.x(q[1])
      
      # CS sends her qubit to UC
      qc.barrier()
      
      #  apply cx-gate as CNOT(CS's-qubit,UC's-qubit)
      qc.cx(q[1],q[0])
      
      # apply h-gate (Hadamard) to the CS's qubit
      qc.h(q[1])
      
      # measure both qubits
      qc.barrier()
      qc.measure(q,c)
      
      # draw the circuit in Qiskit's reading order
      display(qc.draw(output='mpl',reverse_bits=True))
      
      # compare the results with pair (a,b)
      job = execute(qc,Aer.get_backend('qasm_simulator'),shots=100)
      counts = job.result().get_counts(qc)
      print(pair,"-->",counts)
      for s in counts:
        
        l.extend(s)
        tpassword3 = (''.join(l))
      # Merging the CS's transferred password at UC end
      

      #  Storing  received password in in local variable.
      # Printing that your password has been successfully received and the matching has been started with the stored password available in UC database.

        # open the UC database file corresponding to CS.

      #search for corresponding identity in saved list and extract the corresponding password for that identity.
       # match the received password with the extracted corresponding password
        
  with open('UCS_database.txt', 'r') as filehandle:
    for a in filehandle:
      x = a.strip().split("\t")
      
      print(type(x[0]))
      if str(identity) == x[0] :
        print("CS identity matches")
        if tpassword3 == x[1] :
          print("legal CS")
          return 0;
        else :
          print("CS password not match")
          return 1;
      else:
        continue
  print("CS identity not found")
  return 1;

        #  If match is successful, print legal CS             
      # This concludes that the CS has been successfully authenticated using SDC.

# import all necessary objects and methods for quantum circuits
from qiskit import QuantumRegister, ClassicalRegister, QuantumCircuit, execute, Aer

def EVPPreauthentication(Vreq):

  # First CS is pre-authenticated
  print("Vreq received at CS")
  print("Authentication process of CS started with UC")
  
  CSlegal = CSPreauthentication(identity)
  if CSlegal == 0:
    print ("Authentication process of EV started with UC")
  else :
    print("CS pre-authentication fails!")
  # split Vreq in HMAC, identity2, and timestamp

  length = len(Vreq)
  timestamp = Vreq[length - 4:length]
  identity2 = Vreq[length - 68:length - 4]
  hmacvalue = Vreq[0:length-68]  
  zz = hmacvalue + identity2 + timestamp # zz should match with vreq
  
  


  password4 = input("EV - Input your password for pre-authentication (Enter 8 bits either (0/1)): ")  # EV enters 8 bits password which is used at the time of registration and press enter
  print("Your entered password for pre-authentication is: ", password4)
  print("Authentication process of EV started")
  EVlegal = EVPreauthentication(identity2, password4)
  if EVlegal == 0:
    print ("Since EV successfully authenticated, pseudo-identity generation begins")
    phase3(identity2, password4)
  else :
    print(" Since EV authentication fails so, closing the connection")

if __name__ == "__main__":
  
  identity = Random.new().read(8) #creating an identity for CS
  
  CSregistration(identity)
  identity1 = Random.new().read(8)                # creating an identity for EV
                                                  # Making not translation of identity of EV
  
  a = BitArray(bytes=identity1)
  b = a.bin
  
  c = [str(1-int(b[i])) for i in range(len(b))]
  
  d = ''.join(c)
  

  fingerprint = Random.new().read(8)             # Generating biological characteristics
  e = BitArray(bytes=fingerprint).bin
  # Xoring the not translation of identity of EV with biological characteristics
  
  identity2 = int(d,2) ^ int(e,2)
  f = '{0:08b}'.format(identity2)

  identity2 = f
  EVregistration(identity2)

  ####################################################################################################
   #####################################################################################################
                  ###########   Phase 2 and Phase 3 of QSKA   ########################
   ######################################################################################################
   ########################################################################################################

 
  print("EV Pre-authentication process starts")
  password = input("Input your password for calculating Hmac to be sent in Vreq (Enter 8 bits either (0/1)): ")  # EV enters 8 bits password and press enter
  print("Your entered password is: ", password) 
  
  aakey = hashlib.sha256(str.encode(password)).digest()

  
  s = bytes(identity2, 'utf-8')
  s2 = bytes(identity2, 'latin-1')
  identity2 = s
  
  M = hmac.new(s2, aakey, hashlib.sha256).digest()
  print("HMAC created")
  
  # Generate a timestamp
  timestamp = Random.new().read(4)   

  # Concatenate HMAC, encrypted identity (identity2) and timestamp and stores it in Vreq
      
  Vrequest = M + identity2 + timestamp
  print("Vreq Created successfully!")
  print("Vreq transferred to CS")
  
  # calling Ev preauthentication phase  

  EVPPreauthentication(Vrequest)         

####################################################################################################
   #####################################################################################################
                  ###########   Phase 4 of QSKA   ########################
   ######################################################################################################
   ########################################################################################################


  print("Phase 4 begins")
  print("Starting pseudo-identity search in EV database")
  with open('EV_database.txt', 'r') as filehandle:
    for a in filehandle:
      x = a.strip().split("\t")
      
      
      if str(identity2,'utf-8') == x[0] :
        print("Accessing EV database for pseudoidentity")
        pidentity = x[3]
        sessionkey1 = input(" EV- Input your sessionkey for calculating M to be sent in Creq (Enter 8 bits either (0/1)): ")  # EV enters 8 bits password and press enter
        print("Your entered password is: ", sessionkey1) 
        
        ctext = phase4(sessionkey1, pidentity)
        crequest = ctext
        ptext1 = msgverification(pidentity, crequest)
        if ptext1 == 1:
          print("Unsuccessful verification")
        else:
          print("Succesful verification")




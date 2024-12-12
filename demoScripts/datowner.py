#datowner.py

#A simplifed implementation of the Group key generation for a Data Owner in NDN NAC.
#Provides asymmetric encryption (public) key (used by producer.py)
#Provides asymmetric decryption (private) key (used by consumer.py) after exchange with consumer.py

#Run subprocess to generate new RSA keypair for use as Group key
import rsa
groupEncKey, groupDecKey = rsa.newkeys(2048)
print("GROUP KEYS CREATED ON DATA OWNER")
#print("%s\n%s"%(groupEncKey, groupDecKey))

#convert keys into byte files
groupEncKey = groupEncKey.save_pkcs1()
groupDecKey = groupDecKey.save_pkcs1()

#save keys as files on data owner
f = open('groupEncKey', 'wb')
f.write(groupEncKey)
f.close()
f = open('groupDecKey', 'wb')
f.write(groupDecKey)
f.close()

#SOCKET ISSUES ENCOUNTERED IN FABRIC DURING TESTING
# Create socket and wait for connections
#import socket
#import os
#port = 4025
#listenSocket = socket.socket()
#sendSocket = socket.socket()
#listenSocket.bind((socket.gethostname(), port))
#listenSocket.listen(3)
#for i in range(3):#restricted so this closes automatically
#    print("Listening %d."%(i))
#    listenConnection, addr = listenSocket.accept()
#    print("Connected from address ",addr)
#    request = listenConnection.recv(2048)
#    while (request):
#        print(request)
#    #TODO handle request
#    #If request starts with Prod, use the included public key to encrypt the public key and reply with it
#    #If request starts with Auth, use the public key in request to encrypt and send a file to the source (listed in request)
#    listenConnection.close()
#    print("Connection %d done."%(i))

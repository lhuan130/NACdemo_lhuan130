#consumer.py

#Performs the decryption process of a NDN NAC consumer after the encrypted group key is provided.

import rsa

#Retrieve consumer private key to prepare for decrpytion
f = open('consumerPrivateKey', 'rb')
consumerPrivateKeyBytes = f.read()
f.close()
consumerPrivateKey = rsa.PrivateKey.load_pkcs1(consumerPrivateKeyBytes)
print("CONSUMER PRIVATE KEY RETRIEVED")

#Retrieve contents to be decrypted (content, content key)
f = open("contentEncrypted", 'rb')
contentBytes = f.read()
f.close()
f = open("encryptedContentKey", 'rb')
contentKeyBytes = f.read()
f.close()
print("ENCRYPTED CONTENT AND ENCRYPTED CONTENT KEY ACCESSED ON CONSUMER")

#Retrieve segments of Group decryption key
from os import listdir
from os.path import isfile, join
keySegs = ["keySegments/"+f for f in listdir("keySegments") if isfile(join("keySegments", f))]
keySegs.sort()
keyData = bytearray()
for keySeg in keySegs:
    f = open(keySeg, 'rb')
    keySegBytes = f.read()
    f.close()
    keyData.extend(rsa.decrypt(keySegBytes, consumerPrivateKey))
#Reconstruct Group decryption key
groupDecryptKey = rsa.PrivateKey.load_pkcs1(bytes(keyData))
print("GROUP DECRYPTION KEY RECONSTRUCTED AT CONSUMER")

#Decrypt content key
contentKeyBytes = rsa.decrypt(contentKeyBytes, groupDecryptKey)
print("CONTENT KEY RECOVERED")

#Decrypt content
from cryptography.fernet import Fernet
cryptorModule = Fernet(contentKeyBytes)
decryptedContent = cryptorModule.decrypt(contentBytes)
#print(decryptedContent)

#Save decrypted content to file
f = open("decryptedContent.txt", 'w')
f.write(decryptedContent.decode())
f.close()

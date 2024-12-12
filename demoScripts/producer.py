#producer.py

#Generate symmetric key
from cryptography.fernet import Fernet
contentKey = Fernet.generate_key()#default is 32-byte (256 bit)
print("CONTENT KEY GENERATED ON PRODUCER")
#print(contentKey)
cryptorModule = Fernet(contentKey)
#Encrypt content using symmetric key
fileAction = open("content.txt", 'r')
contentTxt = "".join(fileAction.readlines())
fileAction.close()
encryptedContent = cryptorModule.encrypt(contentTxt.encode())
print("CONTENT ENCRYPTED ON PRODUCER")
#print(encryptedContent)

#Saved encrypted content
f = open("contentEncrypted", 'wb')
f.write(encryptedContent)
f.close()

import rsa

#Collect Group encryption from file system
f = open("groupEncKey",'rb')
groupEncKeyBytes = f.read()
f.close()
#print(groupEncKeyBytes)

print("\nGROUP ENCRYPTION KEY ACQUIRED")
groupEncKey = rsa.PublicKey.load_pkcs1(groupEncKeyBytes)
#print(groupEncKey)

#Encrypt content key using Group encryption key
encryptedKey = rsa.encrypt(contentKey, groupEncKey)
print("\nCONTENT KEY ENCRYPTED")
#print(encryptedKey)

#save encrypted content key
f = open("encryptedContentKey", 'wb')
f.write(encryptedKey)
f.close()

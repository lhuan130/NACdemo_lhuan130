#datowner2.py

#Generates an encrypted version (using consumer public key) of Group decryption key
import rsa

f = open("consumerPublicKey",'rb')
consumerPublicKeyBytes = f.read()
f.close()

#extract consumer encryption key
consumerPublicKey = rsa.PublicKey.load_pkcs1(consumerPublicKeyBytes)
print("CONSUMER PUBLIC KEY COLLECTED ON DATA OWNER")
#print(consumerPublicKey)

#collect Group decryption key from files
f = open("groupDecKey",'rb')
groupDecKeyBytes = f.read()
f.close()

#Segment Group decryption key for successful RSA encryption and transfer to Consumer
print("SEGMENTING DECRYPTION KEY FOR SECURE TRANSFER")
import math
RSA_LEN_LIMIT = 245
lastPack = math.ceil(len(groupDecKeyBytes) / RSA_LEN_LIMIT)
for i in range(1, lastPack):
    gdkSeg = groupDecKeyBytes[((i-1)*RSA_LEN_LIMIT):(i*RSA_LEN_LIMIT)]
    segName = "keySegments/groupDecKeySeg"+str(i)
    encryptedDecryptKeySeg = rsa.encrypt(gdkSeg, consumerPublicKey)
    f = open(segName, 'wb')
    f.write(encryptedDecryptKeySeg)
    f.close()
gdkSeg = groupDecKeyBytes[(RSA_LEN_LIMIT*(lastPack-1)):]
segName = "keySegments/groupDecKeySeg"+str(lastPack)
encryptedDecryptKeySeg = rsa.encrypt(gdkSeg, consumerPublicKey)
f = open(segName, 'wb')
f.write(encryptedDecryptKeySeg)
f.close()
print("SEGMENTS AVAILBLE FOR TRANSFER")

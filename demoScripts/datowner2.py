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

#SO, a note on the segmented RSA procedure used above.

#This is not actually recommended. RSA has a 245-byte limit per encryption chunk, meaning that the weirdly long Group decryption key
# actually uses around 7 segments to encrypt. This would actually add an overhead of at least 11 bytes per chunk. For this scenario
# I go against the recommendations to ensure the entire Group decryption key actually interacts and is encrypted in some way by the
# Consumer public key; in practice it should be used to secure an AES exchange for another symmetric key to protect the Group
# decryption key in-transit.

#Part of the reason this segmented method is not recommended is that the security of the chunk splitting is not well studied
# compared to AES's known effectiveness.

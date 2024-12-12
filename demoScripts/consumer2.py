#consumer2.py

#Performs the keygen process of a NDN NAC consumer.


#Run subprocess to generate new RSA keypair for use as consumer key pair
import rsa
consumerPublicKey, consumerPrivateKey = rsa.newkeys(2048)
print("CONSUMER KEY PAIR GENERATED")
#print("%s\n%s"%(consumerPublicKey, consumerPrivateKey))

#convert keys into byte files
consumerPublicKey = consumerPublicKey.save_pkcs1()
consumerPrivateKey = consumerPrivateKey.save_pkcs1()

#save keys as files on consumer
f = open('consumerPublicKey', 'wb')
f.write(consumerPublicKey)
f.close()
f = open('consumerPrivateKey', 'wb')
f.write(consumerPrivateKey)
f.close()

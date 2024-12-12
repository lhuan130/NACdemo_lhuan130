#ndnroute.py

#Serves to forward communication between Consumer, Data Owner, and Producer.
#Caches encrypted content from Producer.
#Supplies requests for encrypted content from Consumer.

#Start this on the router node and it will perform its duty on that node.

port = 4025

listenSocket = socket.socket()
sendSocket = socket.socket()
listenSocket.bind((socket.gethostname(), port))

listenSocket.listen(3)
i = 0
while True:
    print("Listening %d."%(i))
    listenConnection, addr = listenSocket.accept()
    print("Connected from address ",addr)
    request = listenConnection.recv(2048)
    while (request):
        print(request)
    #TODO handle request
    listenConnection.close()
    print("Connection %d done."%(i))

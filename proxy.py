import sys
import socket
import threading

def server_loop(local_host,local_port,remote_host,remote_port,recieve_first):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((local_host,local_port))
    except:
        print "[!!] Failed to listen on %s:%d" % (local_host,local_port)
        print "[!!] Check for other listening sockets or correct permissions."
        sys.exit(0)
        print "[*] Listening on %s:%d" % (local_host,local_port)

        server.listen(5)

        while True:
            client_socket, addr = server.accept()

            # print out local connection information
            print "[==>] Recieved incoming connection from %s:%d" % (addr[0],addr[1])

            # start a thread talking to the remote host
            proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket,remote_host,remote_port,recieve_first))

            proxy_thread.start()

def proxy_handler(client_socket, remote_host, remote_port, recieve_first):

    # connect to the remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host,remote_port))

    # recieve data from the remote end if neccesary
    if receives_first:

        remote_buffer = recieve_from(remote_socket)
        hexdump(remote_buffer)

        # send it to our response handler
        remote_buffer = response_handler(remote_buffer)

        # if we have data to send to our local client, send it
        if len(remote_buffer):
            print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
            client_socket.send(remote_buffer)

    # now lets loop and read from local, send to remote, send to local
    # rinse, wash, repeat
    while True:

        # read from local host
        local_buffer = recieve_from(client_socket)

        if len(local_buffer):

            print "[==>] Recieved %d bytes from localhost." % len(local_buffer)
            hexdump(local_buffer)

            # send it to our request handler
            local_buffer = request_handler(local_buffer)

            # send off the data to the remote host
            remote_socket.send(local_buffer)
            print "[==>] Sent to remote."

            # recieve the response
            remote_buffer = recieve_from(remote_socket)

            if len(remote_buffer):

                print "[<==] Recieved %d bytes from remote." % len(remote_buffer)
                hexdump(remote_buffer)

                # send to our response handler
                remote_buffer = response_handler(remote_buffer)

                # send the response to the local socket
                client_socket.send(remote_buffer)

                print "[<==] Sent to localhost."

            # if no more data on either side, close the connection
            if not len(local_buffer) or not len(remote_buffer):
                client_socket.close()
                remote_socket.close()
                print "[*] No more data. Closing connections."

                break

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2

    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append( b"%04X %-*s" % (i, length*(digits + 1), hexa, text))

    print b'\n'.join(result)

def recieve_from(connection):

    buffer = ""

    # We set a 2 second timeout; depending on your target, this may need to be
    # adjusted
    connection.settimeout(2)

    try:
        # keep reading the buffer until the data runs out or time out
        while True:
            data = connection.recv(4096)

            if not data:
                break
            buffer += data

    except:
        pass
    return buffer

# modify any requests destined for the remote host
def request_handler(buffer):
    # perform packet modifications
    return buffer

# modify any responses destined for the local host
def response_handler(buffer):
    # perform packet modifications
    return buffer

def main():

    # no fancy command line parsing here
    if len(sys.argv[1:]) != 5:
        print "Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [recieve_first]"
        print "Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
        sys.exit(0)

    # setup local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    # setup remote target
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    # this tells the proxy to connect and recieve data
    # before sending to the remote host
    recieve_first = sys.argv[5]

    if "True" in recieve_first:
        recieve_first = True
    else:
        recieve_first = False

    # now sping up our listening socket
    server_loop(local_host,local_port,remote_host,remote_port,recieve_first)

main()

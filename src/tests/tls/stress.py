#!/usr/bin/env python3
import multiprocessing
import time
import socket
import ssl
import logging

class SSLClient:
    def __init__(self, ip, client_cert_file_location, trusted_cas_file_location):
        self.client_cert_file_location = client_cert_file_location
        self.trusted_cas_file_location = trusted_cas_file_location
        self.socket: ssl.SSLSocket = self.connect_to_server(ip, 2083, self.client_cert_file_location, self.trusted_cas_file_location)


    def connect_to_server(self, ip, port, client_cert_file, ca_file_location): 
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(certfile=client_cert_file, password='whatever')

            context.load_verify_locations(cafile=ca_file_location)
            context.check_hostname = False
            sock = context.wrap_socket(sock, server_hostname=ip)
            
            connection =  sock.connect((ip, int(port)))  
            return sock
            
        except Exception as e:
            logging.error(f'Radius tcp monitor: RADIUS server {ip} is DOWN. err: ' + str(e))
            return None


def send_stuff(x):
    try:
        test = SSLClient('127.0.0.1', '../../../raddb/certs/client.pem', '../../../raddb/certs/ca.pem')

        test.socket.send(b'asdlkfjasldkfj')
        test.socket.shutdown(socket.SHUT_WR)
        test.socket.recv(1024)
        test.socket.close()
    except Exception as e: 
        print('error while sending things')
    finally:
        try:
            test.socket.close()
        except: 
            pass




if __name__ == '__main__':
    with multiprocessing.Pool(16) as p: 
        while True:
            p.map(send_stuff, range(400))
            time.sleep(1)

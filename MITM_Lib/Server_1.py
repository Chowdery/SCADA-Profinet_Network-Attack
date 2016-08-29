#!/usr/bin/python

__author__ = 'Nicholas Rodofile'
import socket
import atexit


class Server(object):
    def __init__(self, victim, port):
        self.listen = True
        host = ''        # Symbolic name meaning all available interfaces
        self.port = port     # Arbitrary non-privileged port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.listen(1)
        self.conn = None
        self.address = None
        self.conn, self.addr = self.socket.accept()

        atexit.register(self.close_socket)
        print('Connected by', self.address)
        while self.listen:
            data = self.conn.recv(1024)
            if not data:
                break
            self.conn.sendall(data)
            print data
        self.conn.close()

    def close_socket(self):
        self.conn.close()

s = Server(None, 20000)


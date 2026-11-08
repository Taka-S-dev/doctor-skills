"""Traffic programs run inside the lab containers. Only talks to the lab network."""
import argparse
import socket
import time


def server(args):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", args.port))
    listener.listen(16)
    while True:
        connection, _ = listener.accept()
        try:
            if args.mode == "slow":
                connection.recv(4096)
                time.sleep(1.5)
                connection.sendall(b"response")
                time.sleep(0.5)
            elif args.mode == "flood":
                connection.settimeout(8)
                try:
                    while True:
                        connection.sendall(b"z" * 65536)
                except OSError:
                    pass
            elif args.mode == "close":
                time.sleep(1)
            else:
                connection.settimeout(30)
                while connection.recv(65536):
                    connection.sendall(b"k")
        except OSError:
            pass
        finally:
            connection.close()


def client(args):
    def open_connection(timeout=10, buffer=None):
        sock = socket.socket()
        if buffer:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer)
        sock.settimeout(timeout)
        sock.connect((args.host, args.port))
        return sock

    try:
        if args.mode == "connect":
            open_connection(args.timeout).close()
        elif args.mode == "slow":
            sock = open_connection()
            sock.sendall(b"request")
            sock.recv(4096)
            sock.close()
        elif args.mode == "bulk":
            sock = open_connection(30)
            for _ in range(600):
                sock.sendall(b"d" * 4096)
                sock.recv(16)
            sock.close()
        elif args.mode == "noread":
            sock = open_connection(30, 4096)
            time.sleep(6)
            sock.close()
        elif args.mode == "reconnect":
            for _ in range(4):
                sock = open_connection()
                sock.recv(16)
                sock.close()
                time.sleep(3)
        elif args.mode == "vanish":
            sock = open_connection(30)
            sock.sendall(b"hello")
            sock.recv(16)
            time.sleep(args.pause)
            sock.sendall(b"are you there")
            time.sleep(9)
        elif args.mode == "bigsend":
            sock = open_connection(30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.sendall(b"small")
            sock.recv(16)
            sock.sendall(b"L" * 1400)
            time.sleep(8)
    except OSError as exc:
        print("client error:", exc)


parser = argparse.ArgumentParser()
parser.add_argument("role", choices=("server", "client"))
parser.add_argument("--host", default="server")
parser.add_argument("--port", type=int, default=5000)
parser.add_argument("--mode", default="echo")
parser.add_argument("--timeout", type=float, default=8)
parser.add_argument("--pause", type=float, default=1)
arguments = parser.parse_args()
(server if arguments.role == "server" else client)(arguments)

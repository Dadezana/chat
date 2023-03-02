# Echo client program
import socket
from termcolor import colored
from threading import Thread

def listen_for_messages(s):
    s.settimeout(None)
    try:
        while True:
            data = s.recv(1024)
            data = data.decode()
            # Print message received from other users
            print(data, end="")
    except:
        pass



def main():
    HOST = '127.0.0.1'    # The remote host
    PORT = 58465              # The same port as used by the server
    Thread
    threads = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(colored("[-] Failed to connect to the server", "red"))
            return

        print(colored("[+] Connected", "green"))

        thread = Thread(target=listen_for_messages, args=(s,))
        thread.start()
        try:
            while True:
                msg = input()
                s.sendall(msg.encode())
                if(msg == "/exit"):
                    exit(0)
        except:
            print(colored("[-] Disconnected", "red"))
            exit(0)


if __name__ == '__main__':
    main()
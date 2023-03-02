import socket
from termcolor import colored
from threading import Thread

def handle_connection(conn, addr):
    conn.settimeout(None)
    try:
        with conn:
            print(colored(f'[+] {addr} connected', "green"))
            while True:
                data = conn.recv(1024)
                if not data: break

                data = data.decode()

                if (data == "/exit"):
                    conn.sendall(b"")
                    raise Exception() # to print disconnected message and close the thread
                
                # Print message sent, to keep a log
                print(
                    colored(f"\t\t\t\t{data}", "yellow") + 
                    colored(f"\r{addr}:\n", "white"),
                    end=""
                )
                
                # send message to all clients. All clients will print their own sent messages by themselves
                broadcast_clients(data, addr, [conn])
    except Exception as e:
        remove_client(conn)
        print(colored(f'[-] {addr} disconnected', "red"))
        return
    
    remove_client(conn)
    print(colored(f'[-] {addr} disconnected', "red"))
    return
        
# exceptions: clients that don't need to receive the message 
def broadcast_clients(data, addr="Admin: ", exceptions=[]):
    for client in clients:
        if(client in exceptions): continue

        data = (
            colored(f"\t\t\t\t{data}", "yellow") +
            colored(f"\r{addr}:\n", "white")
        ).encode()

        client.sendall(data)
    return

def remove_client(conn):
    clients.remove(conn)



def main():
    HOST = ''                 # Symbolic name meaning all available interfaces
    PORT = 58465              # Arbitrary non-privileged port

    global clients
    clients = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        while True:
            s.listen(1)
            conn, addr = s.accept()
            clients.append(conn)
            Thread(target=handle_connection, args=(conn, addr)).start()
        


if __name__ == '__main__':
    main()

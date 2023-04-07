import socket
from termcolor import colored
from threading import Thread
from time import sleep

SECONDS_RANGE = 5
MAX_MESSAGES_PER_SECOND = 1   # 5 messages in SECONDS_RANGE seconds

# Just to be able do decrement the variable in another Thread
class Msg:
    num_msg_sent = 0
    stop_thread = False

def handle_connection(conn : socket.socket, addr):
    conn.settimeout(None)
    msg = Msg()

    conn.sendall(b"/ok")

    nickname = conn.recv(1024).decode()

    if "/invalid_nick" in nickname:
        remove_client(conn)
        conn.close()
        return

    x = Thread(target=decrement_num_msg_sent, args=[msg])
    x.start()
    
    try:
        with conn:
            print(colored(f'[+] {addr} - {nickname} connected', "green"))
            # Wait for messages
            while True:
                data = conn.recv(4096)
                if not data: break

                data = data.decode()

                if (data == "/exit"):
                    conn.sendall(b"")
                    raise Exception() # to print disconnected message and close the thread

                msg.num_msg_sent += 1

                # Check for number of messages sent within SECONDS_RANGE seconds
                if is_spam(msg.num_msg_sent):
                    banned_ips.append(str(addr[0]))
                    conn.sendall(b"/ban")
                    remove_client(conn)
                    print(colored(f"=> {addr} - {nickname} banned.", "red", attrs=["bold"]))
                    raise Exception()
                
                # Print message sent, to keep a log
                print(
                    colored(f"\t\t\t\t{data}", "yellow") + 
                    colored(f"\r{nickname}:\n", "white"),
                    end=""
                )
                
                # send message to all clients. All clients will print their own sent messages by themselves
                broadcast_clients(data, nickname, [conn])
    except Exception as e:
        pass
    
    msg.stop_thread = True
    remove_client(conn)
    conn.close()
    print(colored(f'[-] {addr} - {nickname} disconnected', "red"))
    return

def is_spam(num_msg_sent):
    return (num_msg_sent / SECONDS_RANGE) > MAX_MESSAGES_PER_SECOND

def decrement_num_msg_sent(msg):
    while True:
        sleep(SECONDS_RANGE)
        if msg.num_msg_sent > 0:
            msg.num_msg_sent -= 1
        if msg.stop_thread:
            return
    

        
# exceptions: clients that don't need to receive the message 
def broadcast_clients(data, nickname , exceptions=[]):
    for client in clients:
        if(client in exceptions): continue

        data = nickname + "|" + data
        client.sendall(data.encode())
    return

def remove_client(conn):
    try:
        clients.remove(conn)
    except:
        pass



def main():
    HOST = ''                 # all available interfaces
    PORT = 58465              # Arbitrary port

    global clients
    clients = []

    global banned_ips
    banned_ips = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        while True:
            s.listen(1)
            conn, addr = s.accept()
            if str(addr[0]) in banned_ips:
                conn.sendall(b"/ban")
                conn.close()
                continue

            clients.append(conn)
            Thread(target=handle_connection, args=(conn, addr)).start()
        


if __name__ == '__main__':
    main()
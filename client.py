# Echo client program
import socket
from termcolor import colored
from threading import Thread
from time import sleep
import PySimpleGUI as sg
from tkinter import simpledialog, Tk

class UserBannedException(Exception):
    pass

global users
users = []

def listen_for_messages(s : socket.socket):
    s.settimeout(1)

    global users
    win["-USERS-"].update(users)

    while not exit_app:
        try:
            t_nickname, data = s.recv(4096).decode().split(",")
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
        elif t_nickname == "/user_left":
            users.remove(data)
            win["-USERS-"].update(users)
            win["-CHAT HISTORY-"].update(f"=> {data} left the chat\n", text_color_for_value="red", append=True)
            continue
        
        # Print message received
        t_nickname = f"({t_nickname})".ljust(NICKNAME_WIDTH)
        win["-CHAT HISTORY-"].update(f"{t_nickname}", text_color_for_value='#E2CF03', append=True)
        win["-CHAT HISTORY-"].update(data + "\n", text_color_for_value='white', append=True)

def create_window():
    
    CHAT_WIDTH = 85
    CHAT_HEIGHT = 20
    BUTTON_WIDTH = 25
    BUTTON_HEIGHT = 18
    TEXT_PAD = (0,5)
    chat_row = [
        [
            sg.Multiline(key="-CHAT HISTORY-", size=(CHAT_WIDTH, CHAT_HEIGHT), text_color="white", background_color="#222", font=("default", 11), pad=TEXT_PAD, focus=False, no_scrollbar=True, disabled=True),
            sg.Listbox(users, key="-USERS-", size=(15, CHAT_HEIGHT+8), no_scrollbar=True),
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

            win["-CHAT HISTORY-"].update(f"{nick}", text_color_for_value='#E2CF03', append=True)
            win["-CHAT HISTORY-"].update(data + "\n", text_color_for_value='white', append=True)

            if not banned:
                Thread(target=send_message, args=[data,]).start()
            
    win.close()
    

def connect_to_server():
    HOST = '127.0.0.1'    # The remote host
    PORT = 58465              # The same port used by the server

    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    try:
        s.connect((HOST, PORT))
        command, *data = s.recv(1024).decode().split(",")    # if not banned it contains the users
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

    msg = Tk()
    msg.withdraw()

    global nickname
    nickname = simpledialog.askstring("Nickname", "Enter your nickname: ", parent=msg)
    if (nickname == None):
        send_message("/invalid_nick")
        return False
    
    elif(nickname.strip() == ""):
        print(colored("[-] Nickname not valid", "red"))
        send_message("/invalid_nick")
        return False

    send_message(nickname)
    return True


def send_message(msg):
    global s
    s.sendall(msg.encode())

def main():
    global exit_app
    exit_app = False

    global NICKNAME_WIDTH
    NICKNAME_WIDTH = 15     # space taken up by nickname

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

# Echo client program
import socket
from termcolor import colored
from threading import Thread
from time import sleep
import PySimpleGUI as sg
from tkinter import simpledialog, Tk

class UserBannedException(Exception):
    pass

def listen_for_messages(s : socket.socket):
    # s.settimeout(None)
    while not exit_app:
        try:
            data = s.recv(4096)
            data = data.decode()
            nickname = data.split("|")[0]
            data = data.split("|")[1]
            print(f"{nickname}: {data}")
        
        except Exception:
            continue
        
        # Print message received from other users
        nickname = f"({nickname})".ljust(NICKNAME_WIDTH)
        win["-CHAT HISTORY-"].update(f"{nickname}", text_color_for_value='#E2CF03', append=True)
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
            sg.Listbox(["Connected Users", "Dadezana", "Mario", "Giorgio"], key="-USERS-", size=(15, CHAT_HEIGHT+8), no_scrollbar=True),
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

            Thread(target=send_message, args=[data,]).start()
            
    win.close()
    

def connect_to_server():
    HOST = '127.0.0.1'    # The remote host
    PORT = 58465              # The same port used by the server

    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    try:
        s.connect((HOST, PORT))
        data = s.recv(1024).decode()
        if data == "/ban":
            raise UserBannedException()
        
    except ConnectionRefusedError:
        print(colored("[-] Failed to connect to the server", "red"))
        return False
    
    except UserBannedException:
        print(colored("[-] You have been banned from the server", "red"))
        return False
        
    msg = Tk()
    msg.withdraw()

    global nickname
    nickname = str(simpledialog.askstring("Nickname", "Enter your nickname: ", parent=msg))
    if(nickname.strip() == ""):
        print(colored("[-] Nickname not valid", "red"))
        send_message("/invalid_nick")
        return False
    
    elif (nickname == None):
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

    if not connect_to_server():
        exit(0)

    print(colored("[+] Connected", "green"))

    listen_thread = Thread(target=listen_for_messages, args=(s,))
    listen_thread.start()

    create_window()
    handle_window()




if __name__ == '__main__':
    main()

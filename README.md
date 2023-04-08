# Chat <br>![Linux](https://img.shields.io/badge/-linux-ffd52c?style=for-the-badge&logo=archlinux) ![MacOS](https://img.shields.io/badge/-macos-ffaa01?style=for-the-badge&logo=apple) ![Windows](https://img.shields.io/badge/-windows-1ae?style=for-the-badge&logo=windows)<br> ![Language](https://img.shields.io/badge/language-python-blue?style=for-the-badge&logo=python)<br>

A simple real-time chat program built in python and `pysimplegui` module.<br>
Every message sent by a user is broadcasted to all other connected users.
If a user spams, its ip will be banned until the server is restarted.

# How to run
Install the required libraries
```bash
pip install -r requirements.txt
```
> pysimplegui module is not needed server side
>
### **Server**
```bash
python server.py
```
### **Client**
```bash
python client.py
```
On the client side, modify the `HOST` variable so that it contains the ip address of the server. By default it's `127.0.0.1`



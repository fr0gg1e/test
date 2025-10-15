import socket
from smb.SMBConnection import SMBConnection

# Dane logowania
username = 'twoj_uzytkownik'  # lub ''
password = 'twoje_haslo'      # lub ''
client_machine_name = 'client'
server_name = 'server'
server_ip = '192.168.68.105'
share_name = 'share'
local_ip = '192.168.68.106'  # lokalny adres, z którego chcemy wyjść

# Tworzymy połączenie SMB
conn = SMBConnection(username, password, client_machine_name, server_name, use_ntlm_v2=True)

# Tworzymy socket i wiążemy go do lokalnego IP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((local_ip, 0))  # 0 = dowolny wolny port lokalny
s.connect((server_ip, 445))  # połączenie do serwera SMB

# Przekazujemy socket do SMBConnection
conn.sock = s

# Teraz można listować pliki
files = conn.listPath(share_name, '/')
print("Pliki w udziale:")
for f in files:
    print(f.filename)

conn.close()
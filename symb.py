from smb.SMBConnection import SMBConnection

# Dane logowania
username = ''  
password = ''     '
client_machine_name = 'client' 
server_name = '192.168.68.105'          
server_ip = '192.168.68.105'
share_name = 'share'

# Tworzenie połączenia SMB
conn = SMBConnection(username, password, client_machine_name, server_name, use_ntlm_v2=True)
assert conn.connect(server_ip, 445)  # port SMB może być 139 lub 445

# Pobranie listy plików w udziale
files = conn.listPath(share_name, '/')
print("Pliki w udziale:")
for f in files:
    print(f.filename)

# Pobranie pliku z udziału
remote_file_path = '/asdf.txt'
local_file_path = 'plik_z_udzialu.txt'
with open(local_file_path, 'wb') as file_obj:
    conn.retrieveFile(share_name, remote_file_path, file_obj)

print(f"Pobrano {remote_file_path} jako {local_file_path}")

conn.close()

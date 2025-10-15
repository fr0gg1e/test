from smb.SMBConnection import SMBConnection


username = ''  
password = ''     

client_machine_name = 'client' 
server_name = 'server'         
server_ip = '192.168.68.105'
local_ip = '192.168.68.106'    
share_name = 'share'


conn = SMBConnection(username, password, client_machine_name, server_name, use_ntlm_v2=True, my_name=client_machine_name)
assert conn.connect(server_ip, 445, timeout=10, srcaddr=local_ip)  # port SMB 445 lub 139


files = conn.listPath(share_name, '/')
print("Pliki w udziale:")
for f in files:
    print(f.filename)


remote_file_path = '/asdf.txt'
local_file_path = 'plik_z_udzialu.txt'
with open(local_file_path, 'wb') as file_obj:
    conn.retrieveFile(share_name, remote_file_path, file_obj)

print(f"Pobrano {remote_file_path} jako {local_file_path}")

conn.close()
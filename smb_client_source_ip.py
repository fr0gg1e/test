import socket
from smb.SMBConnection import SMBConnection
from smb import smb_constants
import os

# --- PARAMETRY KONFIGURACYJNE ---
# Adres IP, który ma być użyty jako źródłowy (MUSI być przypisany do Twojego komputera)
SOURCE_IP = '192.168.1.10'  # ZMIEŃ NA SWÓJ ŹRÓDŁOWY IP
SOURCE_PORT = 0             # 0 oznacza, że system wybierze wolny port

# Dane serwera SMB
SERVER_IP = '192.168.1.50'  # ZMIEŃ NA IP SERWERA SMB
SERVER_PORT = 445           # Standardowy port SMB

# Dane uwierzytelniające
USERNAME = 'user'           # ZMIEŃ NA NAZWĘ UŻYTKOWNIKA
PASSWORD = 'password'       # ZMIEŃ NA HASŁO
DOMAIN = 'WORKGROUP'        # ZMIEŃ NA NAZWĘ DOMENY/GRUPY ROBOCZEJ

# Nazwy maszyn (mogą być dowolne, ale muszą być unikalne)
MY_NAME = 'MYCLIENT'
SERVER_NAME = 'SMBSERVER'

# --- FUNKCJA WIĄŻĄCA GNIAZDO ---
def create_bound_socket(source_ip, source_port):
    """Tworzy gniazdo TCP i wiąże je z określonym adresem źródłowym."""
    try:
        # Tworzenie gniazda TCP/IP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Wiązanie gniazda z lokalnym adresem IP i portem
        print(f"Wiązanie gniazda z adresem źródłowym: {source_ip}:{source_port}")
        s.bind((source_ip, source_port))
        
        return s
    except Exception as e:
        print(f"Błąd podczas wiązania gniazda: {e}")
        return None

# --- FUNKCJA TRANSFERU PLIKÓW ---
def smb_transfer_with_source_ip(source_ip, server_ip, username, password, domain):
    # 1. Utworzenie gniazda z wymuszonym adresem źródłowym
    bound_socket = create_bound_socket(source_ip, SOURCE_PORT)
    if not bound_socket:
        return

    # 2. Utworzenie połączenia SMB z użyciem wiązanego gniazda
    conn = SMBConnection(username, password, MY_NAME, SERVER_NAME, domain=domain, use_ntlm_v2=True)
    
    try:
        # Użycie gniazda do nawiązania połączenia TCP
        print(f"Łączenie z serwerem SMB: {server_ip}:{SERVER_PORT}")
        conn.connect(server_ip, SERVER_PORT, sock=bound_socket)
        
        if conn.isLoggedIn():
            print("Pomyślnie zalogowano do serwera SMB.")
            
            # --- PRZYKŁAD OPERACJI: LISTOWANIE UDZIAŁÓW ---
            print("\n--- LISTA UDZIAŁÓW ---")
            shares = conn.listShares()
            for share in shares:
                print(f"  - {share.name}")

            # --- PRZYKŁAD OPERACJI: POBIERANIE PLIKU ---
            # ZMIEŃ NAZWY UDZIAŁU I PLIKU PONIŻEJ
            SHARE_NAME = 'TestShare'
            REMOTE_FILE = 'plik_do_pobrania.txt'
            LOCAL_FILE = 'pobrany_plik.txt'
            
            if os.path.exists(LOCAL_FILE):
                os.remove(LOCAL_FILE)

            print(f"\n--- POBIERANIE PLIKU: {REMOTE_FILE} z {SHARE_NAME} ---")
            try:
                with open(LOCAL_FILE, 'wb') as fp:
                    file_size = conn.retrieveFile(SHARE_NAME, REMOTE_FILE, fp)
                print(f"Pomyślnie pobrano plik {REMOTE_FILE} ({file_size} bajtów) do {LOCAL_FILE}")
            except Exception as e:
                print(f"Błąd podczas pobierania pliku: {e}")

            # --- PRZYKŁAD OPERACJI: PRZESYŁANIE PLIKU ---
            # ZMIEŃ NAZWY UDZIAŁU I PLIKU PONIŻEJ
            UPLOAD_SHARE = 'TestShare'
            UPLOAD_LOCAL_FILE = 'plik_do_wyslania.txt'
            UPLOAD_REMOTE_FILE = 'wyslany_przez_pythona.txt'
            
            # Tworzenie pliku testowego do wysłania
            with open(UPLOAD_LOCAL_FILE, 'w') as f:
                f.write("To jest plik testowy wysłany z wymuszonym adresem źródłowym.")

            print(f"\n--- PRZESYŁANIE PLIKU: {UPLOAD_LOCAL_FILE} do {UPLOAD_SHARE} ---")
            try:
                with open(UPLOAD_LOCAL_FILE, 'rb') as fp:
                    conn.storeFile(UPLOAD_SHARE, UPLOAD_REMOTE_FILE, fp)
                print(f"Pomyślnie przesłano plik {UPLOAD_LOCAL_FILE} jako {UPLOAD_REMOTE_FILE}")
            except Exception as e:
                print(f"Błąd podczas przesyłania pliku: {e}")
            
        else:
            print("Błąd logowania do serwera SMB.")

    except Exception as e:
        print(f"Wystąpił błąd połączenia SMB: {e}")
    finally:
        if conn.isLoggedIn():
            conn.close()
        if bound_socket:
            bound_socket.close()

# --- URUCHOMIENIE ---
if __name__ == "__main__":
    print("--- Klient SMB z Wymuszonym Adresem Źródłowym ---")
    print(f"Docelowy adres źródłowy: {SOURCE_IP}")
    
    # Uruchomienie transferu
    smb_transfer_with_source_ip(SOURCE_IP, SERVER_IP, USERNAME, PASSWORD, DOMAIN)
    
    print("\n--- Koniec działania skryptu ---")

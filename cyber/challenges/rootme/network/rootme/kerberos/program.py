 #!/usr/bin/env python3
"""
Formate un ticket Kerberos TGS-REP (etype 18 - AES256) au format
attendu par hashcat (mode 19700) et l'exporte dans kerberos.txt

Format cible :
$krb5tgs$18$user$REALM$*spn*$checksum$encrypted_part
""" 

import subprocess        

def build_hash(user: str, realm: str, spn: str, checksum: str, encrypted_part: str) -> str:
    # Nettoyage basique : on retire espaces et retours à la ligne parasites
    user = user.strip()
    realm = realm.strip().upper()
    spn = spn.strip()
    checksum = checksum.strip()
    encrypted_part = encrypted_part.strip()

    hash_line = f"$krb5tgs$18${user}${realm}$*{spn}*${checksum}${encrypted_part}"
    return hash_line


def main():
    print("=== Générateur de hash krb5tgs (mode hashcat 19700) ===\n")

    user = input("Nom d'utilisateur (ex: william.dupond) : ")
    realm = input("Realm (ex: CATCORP.LOCAL) : ")
    spn = input("SPN (ex: cifs/DC01.catcorp.local) : ")
    checksum = input("Checksum (premier bloc du cipher, généralement les 32 premiers hex / 16 bytes) : ")
    encrypted_part = input("Encrypted part (reste du cipher complet) : ")

    hash_line = build_hash(user, realm, spn, checksum, encrypted_part)

    print("\n--- Résultat ---")
    print(hash_line)

    output_file = "kerberos.txt"
    with open(output_file, "w") as f:
        f.write(hash_line + "\n")
     
    print(f"\n[+] Hash exporté dans : {output_file}")
    
if __name__ == "__main__":
    main()        

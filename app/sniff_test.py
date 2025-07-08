from scapy.all import sniff

def afficher_paquet(packet):
    print(packet.summary())

print("⏳ En attente de paquets... Appuie sur Ctrl+C pour arrêter.")
sniff(prn=afficher_paquet, count=10)

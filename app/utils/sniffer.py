from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from django.utils import timezone

def process_packet(pkt):
    """
    Analyse un paquet réseau et enregistre ses métadonnées dans la base de données.
    Uniquement si le protocole est TCP, UDP ou ICMP.
    """
    from app.models import TrafficLog

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = None
        src_port = None
        dst_port = None
        length = len(pkt)

        if TCP in pkt:
            protocol = 'TCP'
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            protocol = 'UDP'
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            protocol = 'ICMP'

        # Évite les erreurs d'insertion si aucun protocole n'est trouvé
        if not protocol:
            print(f"⚠️ Paquet IP sans protocole reconnu : {src_ip} → {dst_ip}")
            return

        # Création d'une entrée TrafficLog dans la base
        TrafficLog.objects.create(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            timestamp=timezone.now()
        )
        print(f" {src_ip} → {dst_ip} [{protocol}]")

def start_sniffer():
    """
    Lance le sniffer sur une interface réseau spécifique.
    Affiche la liste des interfaces disponibles.
    """
    interfaces = get_if_list()
    print("INTERFACES DISPONIBLES :", interfaces)

    # À ADAPTER : Nom de ton interface réseau active
    iface_to_use = "Wi-Fi"

    try:
        sniff(iface=iface_to_use, filter="ip", prn=process_packet, store=0)
    except Exception as e:
        print(f"❌ Erreur lors du lancement du sniffer : {e}")

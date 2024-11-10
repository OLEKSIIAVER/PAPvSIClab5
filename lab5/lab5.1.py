from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# Конфігурації
INTERFACE = "Ethernet"  # Назва інтерфейсу для прослуховування
PACKETS_THRESHOLD = 100  # Порогова кількість пакетів для одного джерела
TIME_WINDOW = 10  # Часове вікно в секундах для аналізу активності

# Змінні для аналізу трафіку
packet_count = defaultdict(int)
port_scan_detected = defaultdict(set)
start_time = time.time()


def alert_admin(message):
    """
    Сповіщення адміністратора через друк повідомлення або запис в лог.
    """
    print(f"СПОВІЩЕННЯ: {message}")


def analyze_packet(packet):
    """
    Аналізує кожен захоплений пакет для виявлення підозрілих патернів.
    """
    global start_time
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Відстежуємо кількість пакетів від кожного джерела
        packet_count[src_ip] += 1
        port_scan_detected[src_ip].add(dst_port)

        # Перевірка на сканування портів
        if len(port_scan_detected[src_ip]) > 20:
            alert_admin(f"Підозріле сканування портів з IP: {src_ip}")

        # Перевірка на аномально велику кількість пакетів від одного джерела
        if packet_count[src_ip] > PACKETS_THRESHOLD:
            alert_admin(f"Великий об'єм трафіку від одного джерела IP: {src_ip}")

    # Очищення записів після певного часового вікна
    if time.time() - start_time > TIME_WINDOW:
        packet_count.clear()
        port_scan_detected.clear()
        start_time = time.time()


# Запуск прослуховування мережевого інтерфейсу
print("Запуск перехоплення трафіку")
sniff(iface=INTERFACE, prn=analyze_packet, store=False)

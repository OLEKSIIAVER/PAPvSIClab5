import nmap
import subprocess

class WindowsFirewallConfigurator:
    def __init__(self):
        self.clear_rules()

    def clear_rules(self):
        #Очищує всі раніше створені правила з іменем 'CustomRule_*'.
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=CustomRule_*"])
        print("Всі користувацькі правила брандмауера очищено.")

    def block_ip(self, ip_address):
        #Забороняє вхідний трафік з певної IP-адреси.
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CustomRule_Block_IP", "dir=in", "action=block",
            "remoteip=" + ip_address
        ])
        print(f"Заборонено вхідний трафік з IP-адреси: {ip_address}")

    def restrict_port(self, port):
        #Забороняє вхідний трафік на певний порт.
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CustomRule_Block_Port", "dir=in", "action=block",
            "protocol=TCP", "localport=" + str(port)
        ])
        print(f"Заборонено вхідний трафік на порт: {port}")

class NetworkScanner:
    def __init__(self, ip_range, ports):
        self.scanner = nmap.PortScanner()
        self.ip_range = ip_range
        self.ports = ports
        self.results = {}

    def scan_network(self):
        #Сканує IP-адреси та порти у вказаному діапазоні, збирає інформацію про відкриті порти та сервіси.
        print(f"Початок сканування діапазону IP {self.ip_range} та портів {self.ports}")
        self.scanner.scan(self.ip_range, self.ports, arguments="-sV")  # -sV для отримання версії сервісів

        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                open_ports = []
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in ports:
                        service_name = self.scanner[host][proto][port]['name']
                        version = self.scanner[host][proto][port]['version']
                        open_ports.append((port, service_name, version))
                        print(f"Відкритий порт {port}, сервіс: {service_name}, версія: {version}")
                self.results[host] = open_ports
        return self.results

# Ініціалізація конфігуратора брандмауера та сканера мережі
firewall = WindowsFirewallConfigurator()
scanner = NetworkScanner(ip_range="192.168.0.0/24", ports="22,80,443,8080")

# Запуск сканування
scan_results = scanner.scan_network()

# Інтеграція результатів сканування з брандмауером
for host, open_ports in scan_results.items():
    print(f"\nНалаштування брандмауера для IP: {host}")
    # Блокуємо всі невідомі IP-адреси, окрім довірених
    firewall.block_ip(host)

    for port, service, version in open_ports:
        if service in ["http", "https"]:
            print(f"Виявлено веб-сервіс на порту {port}. Доступ дозволено.")
        else:
            firewall.restrict_port(port)
            print(f"Заборонено доступ до порту {port} (сервіс: {service}, версія: {version})")

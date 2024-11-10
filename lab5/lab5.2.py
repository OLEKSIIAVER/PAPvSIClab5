import subprocess

class WindowsFirewallConfigurator:
    def __init__(self):
        # Очищуємо правила, щоб уникнути дублювання
        self.clear_rules()

    def clear_rules(self):
        """Очищує всі раніше створені правила з іменем 'CustomRule_*'."""
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=CustomRule_*"])
        print("Всі користувацькі правила брандмауера очищено.")

    def block_ip(self, ip_address):
        """Забороняє вхідний трафік з певної IP-адреси."""
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CustomRule_Block_IP", "dir=in", "action=block",
            "remoteip=" + ip_address
        ])
        print(f"Заборонено вхідний трафік з IP-адреси: {ip_address}")

    def block_ip_range(self, ip_range):
        """Забороняє вхідний трафік з певного діапазону IP-адрес."""
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CustomRule_Block_IP_Range", "dir=in", "action=block",
            "remoteip=" + ip_range
        ])
        print(f"Заборонено вхідний трафік з діапазону IP-адрес: {ip_range}")

    def restrict_port(self, port):
        """Забороняє вхідний трафік на певний порт."""
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CustomRule_Block_Port", "dir=in", "action=block",
            "protocol=TCP", "localport=" + str(port)
        ])
        print(f"Заборонено вхідний трафік на порт: {port}")

    def allow_trusted_ip(self, ip_address):
        """Дозволяє вхідний трафік тільки з довіреної IP-адреси."""
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CustomRule_Allow_IP", "dir=in", "action=allow",
            "remoteip=" + ip_address
        ])
        print(f"Дозволено вхідний трафік з довіреної IP-адреси: {ip_address}")

    def allow_specific_service(self, port):
        """Дозволяє вхідний трафік на певний порт."""
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CustomRule_Allow_Port", "dir=in", "action=allow",
            "protocol=TCP", "localport=" + str(port)
        ])
        print(f"Дозволено вхідний трафік на порт: {port}")

# Приклад використання
firewall = WindowsFirewallConfigurator()

# Забороняємо трафік з IP-адреси
firewall.block_ip("192.168.1.10")

# Забороняємо трафік з діапазону IP-адрес
firewall.block_ip_range("192.168.1.0-192.168.1.255")

# Забороняємо доступ до певного порту
firewall.restrict_port(8080)

# Дозволяємо трафік тільки з довіреної IP-адреси
firewall.allow_trusted_ip("192.168.1.100")

# Дозволяємо доступ до певного сервісу (наприклад, порт 22 для SSH)
firewall.allow_specific_service(22)

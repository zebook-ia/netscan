#!/usr/bin/env python3
"""
Scanner de Rede Modular para macOS
Versão: 4.0
Compatibilidade: macOS M3 com 8GB RAM
Dependências: nmap (Homebrew), colorama, tqdm

Módulo principal que coordena todo o processo de reconhecimento de rede:
- Verificação de ambiente e dependências
- Detecção automática de rede
- Varredura completa de dispositivos
- Coleta de informações detalhadas
- Geração de relatórios

Autor: Scanner de Rede Profissional
Data: 2025
"""

import subprocess
import json
import re
import os
import sys
import time
import socket
import threading
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# Importar bibliotecas obrigatórias
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Autoreset para macOS
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# ===========================================================================================
# MÓDULO 1: CLASSES DE DADOS E CONFIGURAÇÕES
# ===========================================================================================

@dataclass
class DeviceInfo:
    """Classe para armazenar informações completas do dispositivo"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os_fingerprint: Optional[str] = None
    open_ports: Optional[List[int]] = None
    services: Optional[List[str]] = None
    device_category: Optional[str] = None
    additional_info: Optional[Dict[str, str]] = None
    scan_timestamp: Optional[str] = None
    response_time: Optional[float] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = []
        if self.additional_info is None:
            self.additional_info = {}
        if self.scan_timestamp is None:
            self.scan_timestamp = datetime.now().isoformat()

@dataclass
class NetworkConfig:
    """Configuração de rede detectada"""
    interface: str
    local_ip: str
    gateway: str
    network_range: str
    subnet_mask: str
    dns_servers: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = []

class ScannerConfig:
    """Configurações do scanner"""
    # Configurações de performance para macOS M3 8GB
    MAX_THREADS = 4  # Limitado para não sobrecarregar
    NMAP_TIMING = "T3"  # Balanceado
    HOST_TIMEOUT = "30s"
    MAX_RETRIES = 2
    
    # Portas comuns para scanning
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1723, 3389, 5900, 8080, 8443, 9100, 10000, 5000, 5001, 8000,
        8888, 9000, 3000, 5432, 3306, 1433, 27017, 6379, 11211, 1900,
        5353, 631, 62078, 49152, 49153, 49154
    ]
    
    # Base de dados OUI (Organizationally Unique Identifier) expandida
    OUI_DATABASE = {
        # Apple
        "00:1B:63": "Apple iPhone/iPad",
        "00:26:BB": "Apple AirPort",
        "00:23:DF": "Apple MacBook",
        "28:CD:C1": "Apple iPhone",
        "84:F3:EB": "Apple MacBook",
        "D8:3A:DD": "Apple iPhone",
        "48:D7:05": "Apple iMac",
        "98:01:A7": "Apple MacBook Pro",
        "E4:CE:8F": "Apple iPad",
        "10:9A:DD": "Apple AirPods",
        "4C:57:CA": "Apple TV",
        "AC:BC:32": "Apple AirPort Express",
        "A4:B1:97": "Apple MacBook Air",
        "3C:22:FB": "Apple iMac",
        "88:E9:FE": "Apple Mac Studio",
        "F0:18:98": "Apple Mac mini",
        
        # Dispositivos de Rede - TP-Link
        "00:50:C2": "TP-Link Router",
        "00:1D:D8": "TP-Link Access Point",
        "6C:19:8F": "TP-Link Wireless",
        "C4:E9:84": "TP-Link Router",
        "EC:08:6B": "TP-Link Archer",
        "50:C7:BF": "TP-Link Deco",
        "B0:A7:B9": "TP-Link Range Extender",
        "14:CC:20": "TP-Link TL Series",
        "18:D6:C7": "TP-Link Omada",
        
        # D-Link
        "00:22:B0": "D-Link Router",
        "00:1F:1F": "D-Link Switch",
        "D8:50:E6": "D-Link Wireless",
        "1C:7E:E5": "D-Link DIR Series",
        "34:08:04": "D-Link DWR Series",
        "C8:D3:A3": "D-Link DAP Series",
        
        # Linksys
        "00:07:7D": "Linksys Router",
        "00:13:46": "Linksys WRT",
        "00:26:5A": "Linksys E-Series",
        "48:F8:B3": "Linksys EA Series",
        "20:AA:4B": "Linksys Velop",
        
        # Cisco
        "00:18:39": "Cisco Router",
        "00:21:29": "Cisco Switch",
        "00:24:01": "Cisco Access Point",
        "CC:EF:48": "Cisco Meraki",
        "88:43:E1": "Cisco Catalyst",
        
        # Netgear
        "28:C6:8E": "Netgear Router",
        "00:90:A9": "Netgear Switch",
        "00:A0:C8": "Netgear Wireless",
        "A0:40:A0": "Netgear Nighthawk",
        "9C:3D:CF": "Netgear Orbi",
        
        # Samsung
        "00:12:FB": "Samsung Smart TV",
        "34:7E:5C": "Samsung Galaxy",
        "78:1F:DB": "Samsung SmartThings",
        "8C:77:12": "Samsung Galaxy Tab",
        "E8:50:8B": "Samsung Smart TV",
        
        # LG
        "B4:E6:2D": "LG Smart TV",
        "00:E0:91": "LG Electronics",
        "64:E5:99": "LG WebOS TV",
        
        # Google/Nest
        "DA:A1:19": "Google Chromecast",
        "6C:AD:F8": "Google Nest",
        "F4:F5:D8": "Google Home",
        "CC:22:3D": "Google Pixel",
        "18:B4:30": "Google Nest Hub",
        
        # Amazon
        "FC:A6:67": "Amazon Echo",
        "44:65:0D": "Amazon Fire TV",
        "84:D6:D0": "Amazon Kindle",
        "F0:81:73": "Amazon Echo Dot",
        "B0:7C:B2": "Amazon Echo Show",
        
        # Xiaomi
        "20:34:FB": "Xiaomi Mi Device",
        "64:16:66": "Xiaomi Redmi",
        "AC:5A:FC": "Xiaomi Router",
        "28:6D:CD": "Xiaomi Mi Box",
        "8C:BE:BE": "Xiaomi Mi Band",
        "DC:44:27": "Xiaomi Mi Pad",
        
        # Raspberry Pi
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Trading",
        "E4:5F:01": "Raspberry Pi 4",
        "28:CD:C1": "Raspberry Pi",
        
        # Máquinas Virtuais
        "00:50:56": "VMware ESX Server",
        "00:0C:29": "VMware Workstation",
        "00:05:69": "VMware GSX Server",
        "08:00:27": "Oracle VirtualBox",
        "52:54:00": "QEMU/KVM Virtual Machine",
        "00:16:3E": "Xen Virtual Machine",
        "00:15:5D": "Microsoft Hyper-V",
        
        # Outros dispositivos comuns
        "00:50:FC": "Realtek Semiconductor",
        "00:C0:02": "Sercomm Corporation",
        "00:E0:4C": "Realtek PCIe GBE",
        "00:17:88": "Philips Hue Bridge",
        "18:B7:9E": "Sonos Speaker",
        "5C:AA:FD": "Sonos Play",
    }

# ===========================================================================================
# MÓDULO 2: UTILITÁRIOS E VERIFICAÇÕES DE AMBIENTE
# ===========================================================================================

class ColorManager:
    """Gerenciador de cores com fallback para sistemas sem colorama"""
    
    def __init__(self):
        self.colors_enabled = COLORAMA_AVAILABLE
    
    def red(self, text: str) -> str:
        return f"{Fore.RED}{text}{Style.RESET_ALL}" if self.colors_enabled else text
    
    def green(self, text: str) -> str:
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if self.colors_enabled else text
    
    def yellow(self, text: str) -> str:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if self.colors_enabled else text
    
    def blue(self, text: str) -> str:
        return f"{Fore.BLUE}{text}{Style.RESET_ALL}" if self.colors_enabled else text
    
    def cyan(self, text: str) -> str:
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if self.colors_enabled else text
    
    def magenta(self, text: str) -> str:
        return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}" if self.colors_enabled else text
    
    def bold(self, text: str) -> str:
        return f"{Style.BRIGHT}{text}{Style.RESET_ALL}" if self.colors_enabled else text

class EnvironmentChecker:
    """Verificador de ambiente e dependências"""
    
    def __init__(self, color_manager: ColorManager):
        self.cm = color_manager
        self.issues = []
    
    def check_python_version(self) -> bool:
        """Verificar versão do Python"""
        version = sys.version_info
        if version.major >= 3 and version.minor >= 7:
            print(self.cm.green(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK"))
            return True
        else:
            self.issues.append(f"Python {version.major}.{version.minor} é muito antigo (mínimo: 3.7)")
            print(self.cm.red(f"❌ Python {version.major}.{version.minor} - Versão inadequada"))
            return False
    
    def check_macos_compatibility(self) -> bool:
        """Verificar compatibilidade com macOS"""
        try:
            result = subprocess.run(['sw_vers'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'ProductVersion:' in line:
                        version = line.split(':')[1].strip()
                        print(self.cm.green(f"✅ macOS {version} detectado"))
                        return True
            return False
        except Exception:
            print(self.cm.yellow("⚠️  Não foi possível detectar versão do macOS"))
            return True  # Assume compatibilidade
    
    def check_nmap_installation(self) -> bool:
        """Verificar instalação e versão do Nmap"""
        try:
            # Verificar se nmap existe
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.issues.append("Nmap não encontrado no PATH")
                print(self.cm.red("❌ Nmap não está instalado"))
                print(self.cm.yellow("💡 Instale com: brew install nmap"))
                return False
            
            # Verificar versão
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                print(self.cm.green(f"✅ {version_line}"))
                
                # Verificar se é uma versão recente
                version_match = re.search(r'version (\d+)\.(\d+)', version_line)
                if version_match:
                    major, minor = int(version_match.group(1)), int(version_match.group(2))
                    if major >= 7 and minor >= 80:
                        return True
                    else:
                        print(self.cm.yellow("⚠️  Versão do Nmap pode ser antiga"))
                        return True
                return True
            else:
                self.issues.append("Nmap instalado mas não funcional")
                print(self.cm.red("❌ Nmap instalado mas não funcional"))
                return False
                
        except subprocess.TimeoutExpired:
            self.issues.append("Timeout ao verificar Nmap")
            print(self.cm.red("❌ Timeout ao verificar Nmap"))
            return False
        except FileNotFoundError:
            self.issues.append("Nmap não encontrado")
            print(self.cm.red("❌ Nmap não encontrado"))
            return False
    
    def check_python_dependencies(self) -> bool:
        """Verificar dependências Python"""
        dependencies_ok = True
        
        # Verificar colorama
        if COLORAMA_AVAILABLE:
            print(self.cm.green("✅ colorama - OK"))
        else:
            self.issues.append("colorama não instalado")
            print(self.cm.red("❌ colorama não instalado"))
            print(self.cm.yellow("💡 Instale com: pip3 install colorama"))
            dependencies_ok = False
        
        # Verificar tqdm
        if TQDM_AVAILABLE:
            print(self.cm.green("✅ tqdm - OK"))
        else:
            self.issues.append("tqdm não instalado")
            print(self.cm.red("❌ tqdm não instalado"))
            print(self.cm.yellow("💡 Instale com: pip3 install tqdm"))
            dependencies_ok = False
        
        return dependencies_ok
    
    def check_network_access(self) -> bool:
        """Verificar acesso à rede"""
        try:
            # Tentar conectar ao gateway local
            result = subprocess.run(['ping', '-c', '1', '-W', '3000', '8.8.8.8'], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                print(self.cm.green("✅ Conectividade de rede - OK"))
                return True
            else:
                print(self.cm.yellow("⚠️  Conectividade limitada"))
                return True  # Pode ainda funcionar localmente
        except Exception:
            print(self.cm.yellow("⚠️  Não foi possível verificar conectividade"))
            return True
    
    def check_permissions(self) -> bool:
        """Verificar permissões necessárias"""
        # Para scans SYN, pode precisar de privilégios
        if os.geteuid() == 0:
            print(self.cm.green("✅ Executando como root - scans completos disponíveis"))
            return True
        else:
            print(self.cm.yellow("⚠️  Executando sem privilégios root - alguns scans podem ser limitados"))
            print(self.cm.yellow("💡 Para scans completos: sudo python3 script.py"))
            return True  # Não é crítico
    
    def run_all_checks(self) -> bool:
        """Executar todas as verificações"""
        print(self.cm.bold("\n🔍 VERIFICANDO AMBIENTE E DEPENDÊNCIAS"))
        print("=" * 50)
        
        checks = [
            ("Versão Python", self.check_python_version),
            ("Compatibilidade macOS", self.check_macos_compatibility),
            ("Instalação Nmap", self.check_nmap_installation),
            ("Dependências Python", self.check_python_dependencies),
            ("Acesso à Rede", self.check_network_access),
            ("Permissões", self.check_permissions),
        ]
        
        all_passed = True
        for check_name, check_func in checks:
            print(f"\n🔸 {check_name}:")
            if not check_func():
                all_passed = False
        
        print("\n" + "=" * 50)
        if all_passed:
            print(self.cm.green("✅ Todas as verificações passaram!"))
        else:
            print(self.cm.red("❌ Algumas verificações falharam:"))
            for issue in self.issues:
                print(self.cm.red(f"  • {issue}"))
            print(self.cm.yellow("\n💡 Resolva os problemas acima antes de continuar"))
        
        return all_passed

# ===========================================================================================
# MÓDULO 3: DETECÇÃO DE REDE
# ===========================================================================================

class NetworkDetector:
    """Detector automático de configuração de rede"""
    
    def __init__(self, color_manager: ColorManager):
        self.cm = color_manager
    
    def get_default_interface(self) -> Optional[str]:
        """Obter interface de rede padrão"""
        try:
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'interface:' in line:
                        interface = line.split(':')[1].strip()
                        return interface
            return None
        except Exception as e:
            print(self.cm.red(f"❌ Erro ao obter interface padrão: {e}"))
            return None
    
    def get_gateway_ip(self) -> Optional[str]:
        """Obter IP do gateway padrão"""
        try:
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                gateway_match = re.search(r'gateway:\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gateway_match:
                    return gateway_match.group(1)
            return None
        except Exception as e:
            print(self.cm.red(f"❌ Erro ao obter gateway: {e}"))
            return None
    
    def get_local_ip_and_mask(self, interface: str) -> Tuple[Optional[str], Optional[str]]:
        """Obter IP local e máscara de sub-rede"""
        try:
            result = subprocess.run(['ifconfig', interface], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Buscar IP e netmask
                ip_pattern = r'inet (\d+\.\d+\.\d+\.\d+).*netmask (0x[0-9a-fA-F]+)'
                match = re.search(ip_pattern, result.stdout)
                
                if match:
                    local_ip = match.group(1)
                    netmask_hex = match.group(2)
                    
                    # Converter netmask hex para decimal
                    netmask_int = int(netmask_hex, 16)
                    netmask_parts = []
                    for i in range(4):
                        netmask_parts.append(str((netmask_int >> (24 - i * 8)) & 0xFF))
                    netmask = '.'.join(netmask_parts)
                    
                    return local_ip, netmask
            
            return None, None
        except Exception as e:
            print(self.cm.red(f"❌ Erro ao obter IP local: {e}"))
            return None, None
    
    def calculate_network_range(self, ip: str, netmask: str) -> Optional[str]:
        """Calcular range da rede baseado no IP e máscara"""
        try:
            # Converter máscara para CIDR
            netmask_parts = [int(part) for part in netmask.split('.')]
            cidr = sum([bin(part).count('1') for part in netmask_parts])
            
            # Criar objeto de rede
            network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
            
            return str(network)
        except Exception as e:
            # Fallback para /24 se não conseguir calcular
            print(self.cm.yellow(f"⚠️  Usando /24 como fallback: {e}"))
            ip_parts = ip.split('.')
            return f"{'.'.join(ip_parts[:3])}.0/24"
    
    def get_dns_servers(self) -> List[str]:
        """Obter servidores DNS configurados"""
        dns_servers = []
        try:
            result = subprocess.run(['scutil', '--dns'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                dns_pattern = r'nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)'
                matches = re.findall(dns_pattern, result.stdout)
                dns_servers = list(set(matches))  # Remover duplicatas
                
        except Exception:
            # Fallback para DNS públicos
            dns_servers = ['8.8.8.8', '1.1.1.1']
        
        return dns_servers
    
    def detect_network_config(self) -> Optional[NetworkConfig]:
        """Detectar configuração completa da rede"""
        print(self.cm.bold("\n🌐 DETECTANDO CONFIGURAÇÃO DE REDE"))
        print("=" * 50)
        
        # Obter interface padrão
        interface = self.get_default_interface()
        if not interface:
            print(self.cm.red("❌ Não foi possível detectar interface de rede"))
            return None
        
        print(self.cm.green(f"✅ Interface de rede: {interface}"))
        
        # Obter gateway
        gateway = self.get_gateway_ip()
        if not gateway:
            print(self.cm.red("❌ Não foi possível detectar gateway"))
            return None
        
        print(self.cm.green(f"✅ Gateway: {gateway}"))
        
        # Obter IP local e máscara
        local_ip, netmask = self.get_local_ip_and_mask(interface)
        if not local_ip or not netmask:
            print(self.cm.red("❌ Não foi possível detectar IP local"))
            return None
        
        print(self.cm.green(f"✅ IP Local: {local_ip}"))
        print(self.cm.green(f"✅ Máscara: {netmask}"))
        
        # Calcular range da rede
        network_range = self.calculate_network_range(local_ip, netmask)
        if not network_range:
            print(self.cm.red("❌ Não foi possível calcular o range da rede"))
            return None
        print(self.cm.green(f"✅ Range da Rede: {network_range}"))
        
        # Obter DNS
        dns_servers = self.get_dns_servers()
        if dns_servers:
            print(self.cm.green(f"✅ Servidores DNS: {', '.join(dns_servers)}"))
        
        return NetworkConfig(
            interface=interface,
            local_ip=local_ip,
            gateway=gateway,
            network_range=network_range,
            subnet_mask=netmask,
            dns_servers=dns_servers
        )

# ===========================================================================================
# MÓDULO 4: SCANNER DE DISPOSITIVOS
# ===========================================================================================

class DeviceScanner:
    """Scanner de dispositivos com análise detalhada"""
    
    def __init__(self, color_manager: ColorManager, network_config: NetworkConfig):
        self.cm = color_manager
        self.network_config = network_config
        self.config = ScannerConfig()
    
    def ping_sweep(self) -> List[str]:
        """Fazer ping sweep para descobrir hosts ativos, com fallback se nmap falhar por dnet."""
        print(self.cm.bold("\n🔍 DESCOBRINDO DISPOSITIVOS ATIVOS"))
        print("=" * 50)
        
        network = self.network_config.network_range
        if not network:
            print(self.cm.red("❌ Range de rede não definido."))
            return []
        print(f"🎯 Escaneando rede: {network}")
        
        try:
            cmd = [
                'nmap', '-sn', f'-{self.config.NMAP_TIMING}',
                '--host-timeout', self.config.HOST_TIMEOUT,
                network
            ]
            
            print(self.cm.yellow("⏳ Executando ping sweep (nmap)..."))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Fallback se erro dnet
            if result.returncode != 0 or 'dnet: Failed to open device' in result.stderr:
                print(self.cm.red(f"❌ Erro no ping sweep com nmap: {result.stderr.strip()}"))
                print(self.cm.yellow("⚠️  Tentando varredura alternativa baseada em ping ICMP (pode ser mais lenta)..."))
                return self.ping_sweep_fallback(network)
            
            # Extrair IPs dos hosts ativos
            ip_pattern = r'Nmap scan report for .*?\(?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?'
            active_hosts = re.findall(ip_pattern, result.stdout)
            
            print(self.cm.green(f"✅ Encontrados {len(active_hosts)} dispositivos ativos"))
            return active_hosts
            
        except subprocess.TimeoutExpired:
            print(self.cm.red("❌ Timeout no ping sweep"))
            return []
        except Exception as e:
            print(self.cm.red(f"❌ Erro no ping sweep: {e}"))
            print(self.cm.yellow("⚠️  Tentando varredura alternativa baseada em ping ICMP (pode ser mais lenta)..."))
            return self.ping_sweep_fallback(network)

    def ping_sweep_fallback(self, network_cidr: str) -> List[str]:
        """Varredura alternativa baseada em ping ICMP para cada IP do range."""
        try:
            net = ipaddress.IPv4Network(network_cidr, strict=False)
        except Exception as e:
            print(self.cm.red(f"❌ Erro ao interpretar range de rede: {e}"))
            return []
        
        active_hosts = []
        total = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
        ips = [str(ip) for ip in net.hosts()]
        
        print(self.cm.yellow(f"⏳ Pingando {len(ips)} endereços (ICMP)..."))
        if TQDM_AVAILABLE:
            bar = tqdm(total=len(ips), desc="Ping Sweep", ncols=80)
        else:
            bar = None
        
        for ip in ips:
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    active_hosts.append(ip)
            except Exception:
                pass
            if bar:
                bar.update(1)
            else:
                print(f"Testando {ip}...", end='\r')
        if bar:
            bar.close()
        print(self.cm.green(f"\n✅ Encontrados {len(active_hosts)} dispositivos ativos (ICMP)"))
        if len(active_hosts) == 0:
            print(self.cm.yellow("⚠️  Nenhum host respondeu ao ping ICMP. Verifique firewall, permissões e interface de rede."))
        return active_hosts
    
    def identify_device_by_mac(self, mac_address: Optional[str]) -> Tuple[str, str]:
        """Identificar fabricante e tipo de dispositivo pelo MAC"""
        if not mac_address:
            return "Desconhecido", "Dispositivo Genérico"
        
        # Normalizar MAC address
        mac_upper = mac_address.upper().replace('-', ':')
        oui = mac_upper[:8]  # Primeiros 3 octetos
        
        # Buscar na base OUI
        device_info = self.config.OUI_DATABASE.get(oui, "Fabricante Desconhecido")
        
        # Determinar categoria do dispositivo
        device_category = "Dispositivo Genérico"
        device_lower = device_info.lower()
        
        if any(term in device_lower for term in ['router', 'gateway', 'access point', 'switch']):
            device_category = "Equipamento de Rede"
        elif any(term in device_lower for term in ['iphone', 'android', 'galaxy', 'pixel']):
            device_category = "Smartphone"
        elif any(term in device_lower for term in ['ipad', 'tablet']):
            device_category = "Tablet"
        elif any(term in device_lower for term in ['macbook', 'imac', 'laptop', 'desktop']):
            device_category = "Computador"
        elif any(term in device_lower for term in ['tv', 'chromecast', 'fire tv', 'apple tv']):
            device_category = "Smart TV/Streaming"
        elif any(term in device_lower for term in ['echo', 'home', 'nest', 'speaker']):
            device_category = "Smart Speaker/IoT"
        elif any(term in device_lower for term in ['raspberry', 'arduino']):
            device_category = "Microcomputador"
        elif any(term in device_lower for term in ['vmware', 'virtualbox', 'virtual']):
            device_category = "Máquina Virtual"
        elif any(term in device_lower for term in ['printer', 'scanner']):
            device_category = "Impressora/Scanner"
        
        return device_info, device_category
    
    def analyze_open_ports(self, scan_output: str) -> Tuple[List[int], List[str], str]:
        """Analisar portas abertas e serviços"""
        open_ports = []
        services = []
        device_type_hints = []
        
        # Extrair portas abertas
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
        matches = re.findall(port_pattern, scan_output)
        
        for port, protocol, service in matches:
            port_num = int(port)
            open_ports.append(port_num)
            services.append(f"{service} ({protocol})")
            
            # Inferir tipo de dispositivo baseado nos serviços
            if port_num == 22:
                device_type_hints.append("SSH Server")
            elif port_num in [80, 443, 8080, 8443]:
                device_type_hints.append("Web Server")
            elif port_num in [139, 445]:
                device_type_hints.append("Windows/SMB")
            elif port_num == 3389:
                device_type_hints.append("Windows RDP")
            elif port_num == 5900:
                device_type_hints.append("VNC Server")
            elif port_num in [9100, 631]:
                device_type_hints.append("Network Printer")
            elif port_num == 1900:
                device_type_hints.append("UPnP Device")
            elif port_num == 5353:
                device_type_hints.append("Bonjour/mDNS")
            elif port_num == 62078:
                device_type_hints.append("Apple Device")
            elif port_num in [49152, 49153, 49154]:
                device_type_hints.append("Apple AirPlay")
        
        return open_ports, services, " / ".join(set(device_type_hints))
    
    def get_hostname_info(self, scan_output: str) -> Optional[str]:
        """Extrair hostname do output do nmap"""
        hostname_patterns = [
            r'Nmap scan report for (.+?) \(',
            r'rDNS record for \d+\.\d+\.\d+\.\d+: (.+)',
            r'Host (.+?) \('
        ]
        
        for pattern in hostname_patterns:
            match = re.search(pattern, scan_output)
            if match:
                hostname = match.group(1).strip()
                if hostname and not hostname.startswith('('):
                    return hostname
        
        return None
    
    def extract_os_info(self, scan_output: str) -> Optional[str]:
        """Extrair informações do sistema operacional"""
        os_patterns = [
            r'Running: (.+)',
            r'OS details: (.+)',
            r'Aggressive OS guesses: (.+)'
        ]
        
        for pattern in os_patterns:
            match = re.search(pattern, scan_output)
            if match:
                os_info = match.group(1).strip()
                # Pegar apenas a primeira linha se houver múltiplas
                os_info = os_info.split(',')[0].split('\n')[0]
                return os_info
        
        return None
    
    def measure_response_time(self, ip: str) -> Optional[float]:
        """Medir tempo de resposta do dispositivo"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3000', ip],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                time_pattern = r'time=(\d+\.?\d*) ms'
                match = re.search(time_pattern, result.stdout)
                if match:
                    return float(match.group(1))
        except Exception:
            pass
        
        return None
    
    def scan_device_detailed(self, ip: str) -> DeviceInfo:
        """Escanear um dispositivo específico detalhadamente"""
        try:
            # Medir tempo de resposta primeiro
            response_time = self.measure_response_time(ip)
            
            # Montar comando nmap
            ports_str = ','.join(map(str, self.config.COMMON_PORTS))
            cmd = [
                'nmap', '-sS', '-sV', '-O', '--osscan-guess',
                f'-{self.config.NMAP_TIMING}',
                '--host-timeout', self.config.HOST_TIMEOUT,
                '--max-retries', str(self.config.MAX_RETRIES),
                '-p', ports_str, ip
            ]
            
            # Executar scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            scan_output = result.stdout
            
            # Se falhou, tentar scan mais simples ou alternativo
            if result.returncode != 0 or not scan_output.strip() or 'You requested a scan type which requires root privileges.' in result.stderr or 'set up raw socket' in result.stderr or 'dnet: Failed to open device' in result.stderr:
                print(self.cm.yellow(f"⚠️  Falha no scan SYN (-sS) em {ip}. Tentando scan alternativo (-sT TCP Connect)..."))
                cmd_alt = [
                    'nmap', '-sT', '-sV', '-O', '--osscan-guess',
                    f'-{self.config.NMAP_TIMING}',
                    '--host-timeout', self.config.HOST_TIMEOUT,
                    '--max-retries', str(self.config.MAX_RETRIES),
                    '-p', ports_str, ip
                ]
                result = subprocess.run(cmd_alt, capture_output=True, text=True, timeout=180)
                scan_output = result.stdout
                if result.returncode != 0 or not scan_output.strip():
                    # Última tentativa: scan simples
                    cmd_simple = ['nmap', '-sT', '-p', '22,80,443', ip]
                    result = subprocess.run(cmd_simple, capture_output=True, text=True, timeout=60)
                    scan_output = result.stdout
            
            # Extrair informações básicas
            hostname = self.get_hostname_info(scan_output)
            
            # Extrair MAC address e vendor
            mac_match = re.search(r'MAC Address: ([A-Fa-f0-9:]{17}) \((.+?)\)', scan_output)
            mac_address = mac_match.group(1) if mac_match else None
            nmap_vendor = mac_match.group(2) if mac_match else None
            
            # Identificar por MAC
            device_info, device_category = self.identify_device_by_mac(mac_address)
            
            # Usar vendor do nmap se disponível, senão usar do OUI
            vendor = nmap_vendor if nmap_vendor else device_info
            
            # Analisar portas e serviços
            open_ports, services, service_hints = self.analyze_open_ports(scan_output)
            
            # Extrair informações do OS
            os_info = self.extract_os_info(scan_output)
            
            # Combinar informações de tipo de dispositivo
            device_type_parts = []
            if service_hints:
                device_type_parts.append(service_hints)
            if device_category != "Dispositivo Genérico":
                device_type_parts.append(device_category)
            
            device_type = " | ".join(device_type_parts) if device_type_parts else device_category
            
            # Informações adicionais
            additional_info = {}
            if response_time:
                additional_info['response_time_ms'] = response_time
            if os_info:
                additional_info['os_detection'] = os_info
            
            return DeviceInfo(
                ip=ip,
                hostname=hostname,
                mac_address=mac_address,
                vendor=vendor,
                device_type=device_type,
                os_fingerprint=os_info,
                open_ports=open_ports,
                services=services,
                device_category=device_category,
                additional_info=additional_info,
                response_time=response_time
            )
            
        except subprocess.TimeoutExpired:
            return DeviceInfo(
                ip=ip,
                device_type="Timeout no scan",
                device_category="Erro",
                additional_info={'error': 'Timeout durante o scan'}
            )
        except Exception as e:
            return DeviceInfo(
                ip=ip,
                device_type=f"Erro: {str(e)}",
                device_category="Erro",
                additional_info={'error': str(e)}
            )
    
    def scan_all_devices(self, host_list: List[str]) -> List[DeviceInfo]:
        """Escanear todos os dispositivos com barra de progresso"""
        devices = []
        
        print(self.cm.bold(f"\n🔍 ESCANEANDO {len(host_list)} DISPOSITIVOS DETALHADAMENTE"))
        print("=" * 50)
        
        if TQDM_AVAILABLE:
            # Usar tqdm para barra de progresso
            def scan_with_progress():
                with ThreadPoolExecutor(max_workers=self.config.MAX_THREADS) as executor:
                    # Submeter todas as tarefas
                    future_to_ip = {
                        executor.submit(self.scan_device_detailed, ip): ip 
                        for ip in host_list
                    }
                    
                    # Processar resultados com barra de progresso
                    with tqdm(total=len(host_list), desc="Escaneando", 
                             bar_format="{l_bar}%s{bar}%s{r_bar}" % (self.cm.cyan(''), self.cm.cyan('')),
                             ncols=80) as pbar:
                        
                        for future in as_completed(future_to_ip):
                            ip = future_to_ip[future]
                            try:
                                device = future.result()
                                devices.append(device)
                                
                                # Atualizar descrição
                                device_name = (device.vendor or device.device_type or ip)[:20]
                                pbar.set_description(f"✅ {device_name}")
                                
                            except Exception as e:
                                error_device = DeviceInfo(
                                    ip=ip,
                                    device_type="Erro no scan",
                                    additional_info={'error': str(e)}
                                )
                                devices.append(error_device)
                                pbar.set_description(f"❌ {ip}")
                            
                            pbar.update(1)
            
            scan_with_progress()
            
        else:
            # Fallback sem tqdm
            print("⏳ Escaneando dispositivos (sem barra de progresso)...")
            for i, ip in enumerate(host_list, 1):
                print(f"{i}/{len(host_list)}: Escaneando {ip}...")
                device = self.scan_device_detailed(ip)
                devices.append(device)
                device_name = device.vendor or device.device_type or "Concluído"
                print(f"  ✅ {device_name}")
        
        return devices

# ===========================================================================================
# MÓDULO 5: GERAÇÃO DE RELATÓRIOS
# ===========================================================================================

class ReportGenerator:
    """Gerador de relatórios detalhados"""
    
    def __init__(self, color_manager: ColorManager):
        self.cm = color_manager
        self.output_dir = Path("network_scan_results")
        self.output_dir.mkdir(exist_ok=True)
    
    def format_device_summary(self, device: DeviceInfo) -> str:
        """Formatar resumo de um dispositivo"""
        summary_parts = []
        
        # Informações básicas
        summary_parts.append(f"IP: {device.ip}")
        
        if device.hostname:
            summary_parts.append(f"Nome: {device.hostname}")
        
        if device.vendor and device.vendor != "Fabricante Desconhecido":
            summary_parts.append(f"Fabricante: {device.vendor}")
        
        if device.device_category and device.device_category != "Dispositivo Genérico":
            summary_parts.append(f"Categoria: {device.device_category}")
        
        if device.mac_address:
            summary_parts.append(f"MAC: {device.mac_address}")
        
        if device.response_time:
            summary_parts.append(f"Ping: {device.response_time:.1f}ms")
        
        return " | ".join(summary_parts)
    
    def display_scan_results(self, devices: List[DeviceInfo], network_config: NetworkConfig):
        """Exibir resultados do scan na tela"""
        print(self.cm.bold("\n📊 RESULTADOS DO SCAN"))
        print("=" * 70)
        
        # Estatísticas gerais
        total_devices = len(devices)
        devices_with_mac = len([d for d in devices if d.mac_address])
        devices_with_services = len([d for d in devices if d.open_ports])
        
        print(f"🌐 Rede escaneada: {network_config.network_range}")
        print(f"📊 Total de dispositivos: {total_devices}")
        print(f"🆔 Com endereço MAC: {devices_with_mac}")
        print(f"🚪 Com serviços ativos: {devices_with_services}")
        print("")
        
        # Listar dispositivos
        for i, device in enumerate(devices, 1):
            print(f"{i:2d}. {self.format_device_summary(device)}")
            
            # Mostrar detalhes adicionais se disponíveis
            details = []
            if device.os_fingerprint:
                details.append(f"OS: {device.os_fingerprint}")
            if device.open_ports:
                port_list = ', '.join(map(str, device.open_ports[:8]))
                if len(device.open_ports) > 8:
                    port_list += "..."
                details.append(f"Portas: {port_list}")
            
            if details:
                print(f"    {self.cm.cyan(' | '.join(details))}")
            
            print("")
    
    def generate_text_report(self, devices: List[DeviceInfo], network_config: NetworkConfig) -> str:
        """Gerar relatório detalhado em texto"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"network_scan_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            # Cabeçalho do relatório
            f.write("=" * 80 + "\n")
            f.write("RELATÓRIO COMPLETO DE RECONHECIMENTO DE REDE\n")
            f.write("=" * 80 + "\n")
            f.write(f"Data/Hora do Scan: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write(f"Rede Escaneada: {network_config.network_range}\n")
            f.write(f"Gateway: {network_config.gateway}\n")
            f.write(f"IP Local: {network_config.local_ip}\n")
            f.write(f"Interface: {network_config.interface}\n")
            if network_config.dns_servers:
                f.write(f"Servidores DNS: {', '.join(network_config.dns_servers)}\n")
            f.write(f"Total de Dispositivos Encontrados: {len(devices)}\n")
            f.write("\n")
            
            # Resumo por categorias
            categories = {}
            vendors = {}
            
            for device in devices:
                cat = device.device_category or "Não Identificado"
                categories[cat] = categories.get(cat, 0) + 1
                
                vendor = device.vendor or "Desconhecido"
                if vendor != "Fabricante Desconhecido":
                    vendors[vendor] = vendors.get(vendor, 0) + 1
            
            f.write("RESUMO POR CATEGORIAS:\n")
            f.write("-" * 40 + "\n")
            for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {category}: {count} dispositivo(s)\n")
            
            f.write("\nRESUMO POR FABRICANTE:\n")
            f.write("-" * 40 + "\n")
            for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {vendor}: {count} dispositivo(s)\n")
            
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("DETALHES DOS DISPOSITIVOS\n")
            f.write("=" * 80 + "\n")
            
            # Detalhes de cada dispositivo
            for i, device in enumerate(devices, 1):
                f.write(f"\n[{i:02d}] DISPOSITIVO: {device.ip}\n")
                f.write("-" * 50 + "\n")
                
                if device.hostname:
                    f.write(f"Hostname: {device.hostname}\n")
                
                if device.mac_address:
                    f.write(f"Endereço MAC: {device.mac_address}\n")
                
                if device.vendor and device.vendor != "Fabricante Desconhecido":
                    f.write(f"Fabricante: {device.vendor}\n")
                
                if device.device_category:
                    f.write(f"Categoria: {device.device_category}\n")
                
                if device.device_type:
                    f.write(f"Tipo Detectado: {device.device_type}\n")
                
                if device.os_fingerprint:
                    f.write(f"Sistema Operacional: {device.os_fingerprint}\n")
                
                if device.response_time:
                    f.write(f"Tempo de Resposta: {device.response_time:.1f} ms\n")
                
                if device.open_ports:
                    f.write(f"Portas Abertas ({len(device.open_ports)}): {', '.join(map(str, device.open_ports))}\n")
                
                if device.services:
                    f.write(f"Serviços Detectados:\n")
                    for service in device.services:
                        f.write(f"  • {service}\n")
                
                if device.additional_info:
                    f.write("Informações Adicionais:\n")
                    for key, value in device.additional_info.items():
                        f.write(f"  • {key}: {value}\n")
                
                f.write(f"Timestamp do Scan: {device.scan_timestamp}\n")
        
        return str(filename)
    
    def generate_json_report(self, devices: List[DeviceInfo], network_config: NetworkConfig) -> str:
        """Gerar relatório em JSON para processamento automatizado"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"network_scan_{timestamp}.json"
        
        # Converter para formato serializável
        devices_data = []
        for device in devices:
            device_dict = asdict(device)
            devices_data.append(device_dict)
        
        report_data = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "scan_date": datetime.now().strftime("%Y-%m-%d"),
                "scan_time": datetime.now().strftime("%H:%M:%S"),
                "total_devices": len(devices),
                "scanner_version": "4.0",
                "platform": "macOS"
            },
            "network_config": asdict(network_config),
            "summary": {
                "categories": {},
                "vendors": {},
                "services": {}
            },
            "devices": devices_data
        }
        
        # Gerar estatísticas de resumo
        for device in devices:
            # Categorias
            cat = device.device_category or "Não Identificado"
            report_data["summary"]["categories"][cat] = report_data["summary"]["categories"].get(cat, 0) + 1
            
            # Vendors
            vendor = device.vendor or "Desconhecido"
            if vendor != "Fabricante Desconhecido":
                report_data["summary"]["vendors"][vendor] = report_data["summary"]["vendors"].get(vendor, 0) + 1
            
            # Serviços
            for service in device.services or []:
                service_name = service.split('(')[0].strip()  # Remover protocolo
                report_data["summary"]["services"][service_name] = report_data["summary"]["services"].get(service_name, 0) + 1
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        return str(filename)

# ===========================================================================================
# MÓDULO 6: CLASSE PRINCIPAL E COORDENAÇÃO
# ===========================================================================================

class NetworkScannerMain:
    """Classe principal que coordena todo o processo de scanning"""
    
    def __init__(self):
        self.cm = ColorManager()
        self.env_checker = EnvironmentChecker(self.cm)
        self.network_detector = NetworkDetector(self.cm)
        self.report_generator = ReportGenerator(self.cm)
        self.network_config = None
        self.device_scanner = None
    
    def print_banner(self):
        """Exibir banner inicial"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SCANNER DE REDE MODULAR v4.0                             ║
║                        Especializado para macOS M3                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  • Detecção automática de rede                                              ║
║  • Análise detalhada de dispositivos                                        ║
║  • Identificação por MAC address (OUI)                                      ║
║  • Scanning otimizado para 8GB RAM                                          ║
║  • Relatórios em TXT e JSON                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(self.cm.cyan(banner))
    
    def confirm_execution(self) -> bool:
        """Confirmar execução com o usuário"""
        print(self.cm.bold("\n⚠️  AVISO IMPORTANTE"))
        print("Este scanner irá:")
        print("• Analisar toda a rede local")
        print("• Fazer scanning de portas em dispositivos encontrados")
        print("• Coletar informações de identificação")
        print("• Gerar relatórios detalhados")
        print("\n" + self.cm.yellow("Use apenas em redes próprias ou com autorização!"))
        
        while True:
            response = input(f"\n{self.cm.bold('Deseja continuar? (s/N): ')}").strip().lower()
            if response in ['s', 'sim', 'y', 'yes']:
                return True
            elif response in ['n', 'não', 'nao', 'no', ''] or not response:
                return False
            else:
                print(self.cm.red("Por favor, responda 's' para sim ou 'n' para não."))
    
    def run_complete_scan(self) -> bool:
        """Executar o scan completo"""
        start_time = time.time()
        
        try:
            # 1. Verificações de ambiente
            if not self.env_checker.run_all_checks():
                print(self.cm.red("\n❌ Verificações de ambiente falharam!"))
                return False
            
            # 2. Detectar configuração de rede
            self.network_config = self.network_detector.detect_network_config()
            if not self.network_config:
                print(self.cm.red("\n❌ Não foi possível detectar configuração de rede!"))
                return False
            
            # 3. Inicializar scanner de dispositivos
            self.device_scanner = DeviceScanner(self.cm, self.network_config)
            
            # 4. Descobrir hosts ativos
            active_hosts = self.device_scanner.ping_sweep()
            if not active_hosts:
                print(self.cm.yellow("\n⚠️  Nenhum dispositivo ativo encontrado!"))
                return False
            
            # 5. Escanear dispositivos detalhadamente
            devices = self.device_scanner.scan_all_devices(active_hosts)
            
            # 6. Exibir resultados
            self.report_generator.display_scan_results(devices, self.network_config)
            
            # 7. Gerar relatórios
            print(self.cm.bold("\n📝 GERANDO RELATÓRIOS"))
            print("=" * 50)
            
            txt_file = self.report_generator.generate_text_report(devices, self.network_config)
            json_file = self.report_generator.generate_json_report(devices, self.network_config)
            
            print(self.cm.green(f"✅ Relatório TXT: {txt_file}"))
            print(self.cm.green(f"✅ Relatório JSON: {json_file}"))
            
            # 8. Estatísticas finais
            end_time = time.time()
            duration = end_time - start_time
            
            print(self.cm.bold(f"\n🎉 SCAN CONCLUÍDO COM SUCESSO!"))
            print(f"⏱️  Tempo total: {duration:.1f} segundos")
            print(f"📊 Dispositivos encontrados: {len(devices)}")
            print(f"📁 Relatórios salvos em: {self.report_generator.output_dir}")
            
            return True
            
        except KeyboardInterrupt:
            print(self.cm.yellow(f"\n\n⚠️  Scan interrompido pelo usuário"))
            return False
        except Exception as e:
            print(self.cm.red(f"\n❌ Erro durante o scan: {e}"))
            return False
    
    def main(self):
        """Método principal"""
        # Exibir banner
        self.print_banner()
        
        # Confirmar execução
        if not self.confirm_execution():
            print(self.cm.yellow("Operação cancelada pelo usuário."))
            return
        
        # Executar scan
        success = self.run_complete_scan()
        
        if success:
            print(self.cm.green(f"\n✨ Obrigado por usar o Scanner de Rede Modular!"))
        else:
            print(self.cm.red(f"\n❌ Scan não foi concluído com sucesso."))
            sys.exit(1)

# ===========================================================================================
# PONTO DE ENTRADA
# ===========================================================================================

if __name__ == "__main__":
    # Verificar se está rodando no macOS
    if sys.platform != "darwin":
        print("⚠️  Este script foi otimizado para macOS. Pode não funcionar corretamente em outros sistemas.")
    
    # Verificar dependências críticas antes de iniciar
    missing_deps = []
    if not COLORAMA_AVAILABLE:
        missing_deps.append("colorama")
    if not TQDM_AVAILABLE:
        missing_deps.append("tqdm")
    
    if missing_deps:
        print(f"❌ Dependências faltando: {', '.join(missing_deps)}")
        print(f"💡 Instale com: pip3 install {' '.join(missing_deps)}")
        sys.exit(1)
    
    # Inicializar e executar
    scanner = NetworkScannerMain()
    scanner.main()
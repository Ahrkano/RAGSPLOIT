#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import time
from mininet.net import Containernet
from mininet.node import Docker, Switch
from mininet.log import info, setLogLevel

# --- CLASSE CUSTOMIZADA: LINUX BRIDGE ---
class SimpleBridge(Switch):
    "Simple Linux Bridge com MTU ajustado"
    def start(self, controllers):
        self.cmd('ifconfig', self, 'down')
        self.cmd('brctl delbr', self)
        self.cmd('brctl addbr', self)
        self.cmd('brctl stp', self, 'off')
        
        for intf in self.intfs.values():
            if intf.name != self.name:
                self.cmd('brctl addif', self, intf.name)
                self.cmd('ifconfig', intf.name, '0.0.0.0', 'up')
                self.cmd('ifconfig', intf.name, 'promisc')
                # REDUZIR MTU DA PORTA DO SWITCH
                self.cmd('ifconfig', intf.name, 'mtu', '1400')
        
        self.cmd('ifconfig', self, 'up')
        # REDUZIR MTU DA PONTE
        self.cmd('ifconfig', self, 'mtu', '1400')
        
    def stop(self, deleteIntfs=True):
        self.cmd('ifconfig', self, 'down')
        self.cmd('brctl delbr', self)
        super(SimpleBridge, self).stop(deleteIntfs)

# --- PATCH PARA CGROUP V2 ---
def patched_update_resources(self, **kwargs):
    try:
        if kwargs.get('cpu_quota') == -1: return
        self.dcli.update_container(self.dc, **kwargs)
    except: pass
Docker.update_resources = patched_update_resources

def install_deps():
    os.system('apt-get update && apt-get install -y bridge-utils iputils-ping ethtool net-tools iptables')

def prepare_network(node, intf_name):
    info(f'*** Preparando {node.name}...\n')
    node.cmd('apt-get update')
    node.cmd('apt-get install -y iputils-ping ethtool net-tools')
    
    # 1. Desliga Offloading (Hardware Falso)
    node.cmd(f'ethtool -K {intf_name} tx off rx off sg off tso off gso off gro off')
    
    # 2. Ajusta MTU (Evita fragmentacao no Proxmox)
    node.cmd(f'ifconfig {intf_name} mtu 1400')

def nuke_firewall():
    """ Abre todas as portas do firewall para permitir a ponte """
    info('*** DESTRUINDO REGRAS DE FIREWALL (ALLOW ALL) ***\n')
    # Aceita forward por padrao
    os.system('iptables -P FORWARD ACCEPT')
    os.system('iptables -F FORWARD')
    # Tenta inserir regra no topo da cadeia do Docker (se existir)
    os.system('iptables -I DOCKER-USER -j ACCEPT 2>/dev/null')
    os.system('iptables -I DOCKER-ISOLATION-STAGE-1 -j ACCEPT 2>/dev/null')

def topology():
    setLogLevel('info')
    install_deps()
    nuke_firewall() # Aplica correcao de firewall ANTES de criar a rede

    net = Containernet(controller=None)
    
    info('*** Adicionando Hosts\n')
    d1 = net.addDocker('d1', ip='10.0.0.1', mac='00:00:00:00:00:01', dimage="ubuntu:18.04")
    d2 = net.addDocker('d2', ip='10.0.0.2', mac='00:00:00:00:00:02', dimage="ubuntu:18.04")
    
    info('*** Adicionando Switch (Linux Bridge MTU 1400)\n')
    s1 = net.addSwitch('s1', cls=SimpleBridge)
    
    info('*** Criando Links\n')
    net.addLink(d1, s1)
    net.addLink(d2, s1)
    
    info('*** Iniciando a Rede\n')
    net.start()

    prepare_network(d1, 'd1-eth0')
    prepare_network(d2, 'd2-eth0')

    info('*** Configurando ARP Estatico...\n')
    d1.setARP('10.0.0.2', '00:00:00:00:00:02')
    d2.setARP('10.0.0.1', '00:00:00:00:00:01')

    # Reforça firewall apos inicio da rede (Docker as vezes recria regras)
    nuke_firewall()

    info('*** Teste de Conectividade (Ping d1 -> d2)\n')
    print(d1.cmd('ping -c 5 10.0.0.2'))
    
    info('*** Parando a Rede\n')
    net.stop()

if __name__ == '__main__':
    topology()
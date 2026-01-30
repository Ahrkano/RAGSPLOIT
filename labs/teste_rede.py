#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def emptyNet():
    setLogLevel('info')
    
    # Cria a rede
    net = Mininet(controller=Controller)
    
    info('*** Adicionando controller\n')
    net.addController('c0')
    
    info('*** Adicionando hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    
    info('*** Adicionando switch\n')
    s1 = net.addSwitch('s1')
    
    info('*** Criando links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    
    info('*** Iniciando a rede\n')
    net.start()
    
    info('*** Testando conectividade (Ping)\n')
    net.pingAll()
    
    info('*** Iniciando CLI (Comandos manuais)\n')
    # CLI(net) # Descomente se quiser interagir no terminal
    
    info('*** Parando a rede\n')
    net.stop()

if __name__ == '__main__':
    emptyNet()
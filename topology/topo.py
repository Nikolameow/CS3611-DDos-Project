#!/usr/bin/env python3
"""
DDoS 实验拓扑

    h1 (attacker) ─┐
    h2 (attacker) ─┤
    h3 (attacker) ─┼─── s1 (OVS) ─── victim (10.0.0.100)
    h4 (normal)   ─┘

运行: sudo python3 topo.py
进入 mininet CLI 后:
    xterm victim h1 h2 h3 h4   # 打开每台机器的终端
    pingall                     # 验证连通性
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import OVSBridge
from mininet.log import setLogLevel


class DDoSTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        # 三台攻击者
        for i in range(1, 4):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
            self.addLink(h, s1)

        # 正常用户（对照组）
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        self.addLink(h4, s1)

        # 受害者 = 防御网关（合并节点，所有防御代码都跑在这）
        victim = self.addHost('victim', ip='10.0.0.100/24')
        self.addLink(victim, s1)


def run():
    setLogLevel('info')
    net = Mininet(topo=DDoSTopo(), switch=OVSBridge, controller=None)
    net.start()

    # 把项目目录挂进每个 host 的 PATH（host 之间共享宿主机文件系统）
    print("\n[*] 拓扑就绪。项目根目录 = /home/claude/ddos_project (按你的实际路径改)")
    print("[*] 在 CLI 里运行 'xterm victim h1' 等打开终端\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    run()

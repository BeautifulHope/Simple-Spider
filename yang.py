from scapy.all import *

def DataCheck(Info):
    Data = Info.split(" ")
    sum = 0
    for i in Data:
        sum = int('0x' + i, 16) + sum
    check = 0xffff - ((0x0000ffff & sum) + (sum >> 16))
    return check


if __name__ == '__main__':
    packets = sniff(iface="Intel(R) Dual Band Wireless-AC 3165", count=1)

    for p in packets:
        # p.show()
        # print(p.payload.id);
        p.payload.show()
        a = p.payload.version  # 版本
        b = p.payload.ihl  # 头部长度
        a1 = a  + b
        c = p.payload.len  # 总长度
        c1 = hex(c)[-2:]
        d = p.payload.id  # 标识
        d1 = hex(d)[2:-2]
        d2 = hex(d)[-2:]
        e = p.payload.ttl  # 存活时间
        e1 = hex(e)[-2:]
        f = p.payload.proto  # 协议
        g = p.payload.chksum  # 效验和
        print('31',g)
        h = p.payload.src  # 源地址
        i = p.payload.dst  # 目的地址

        packet = ['45', '00', '00', c1, d1, d2, '40', '00', e1, '06',
                  '00', '00',  # 校验位
                  'C0', 'A8', '2B', '42',  # 源IP
                  'B4', 'A3', '19', '26',  # 目的IP
                  ]

        IPH = ''
        for i in range(0, 20):
            if i % 2 == 0 or i == 19:
                IPH = IPH + packet[i]
            else:
                IPH = IPH + packet[i] + ' '
        print('46',IPH)
        IPHcheck = DataCheck(IPH)
        print('47',IPHcheck)
        IPHcheck = str(hex(IPHcheck))[2:]
        IPHcheck = IPHcheck.zfill(4)
        packet[10] = IPHcheck[0:2].upper()
        packet[11] = IPHcheck[2:4].upper()
        print(packet)

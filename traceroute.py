import socket
import re
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import subprocess
import sys


class WhoIsError(Exception):
    def __init__(self, exception_message):
        self.message = exception_message

    def __str__(self):
        return self.message


def get_refer(domain):
    ip = socket.gethostbyname(domain) + '\r\n'
    sock = socket.socket()
    sock.connect(('whois.iana.org', 43))
    sock.send(ip.encode())
    info = sock.recv(1024).decode()
    if re.search(r'status:\s+\w+', info).group(0).split()[-1] == 'RESERVED':
        raise WhoIsError('Reserved IP-address')
    return re.search(r'refer:\s+(.+)', info).group(1)


def whois(address):
    site = get_refer(address)
    address = socket.gethostbyname(address)
    address += '\r\n'
    sock = socket.socket()
    sock.connect((site, 43))
    sock.send(address.encode())
    res = ''
    while True:
        try:
            buf = sock.recv(4096)
        except socket.error:
            raise WhoIsError('Connection error')
        if buf:
            res += buf.decode('utf-8', 'ignore')
        else:
            break
    sock.close()
    error = re.search(r'ERROR.*', res)
    if error is not None:
        raise WhoIsError(error.group(0))

    return res.lower()


def traceroute(domain):
    if sys.platform[0:3] == 'win':
        addresses = win_trace(domain)
    else:
        addresses = linux_trace(domain)
    del addresses[0]
    if socket.gethostbyname(domain) not in addresses:
        addresses.append(socket.gethostbyname(domain))
    return addresses


def win_trace(domain):
    output = subprocess.check_output('tracert -w 1 ' + domain, shell=True)
    output = output.decode('utf-8', 'ignore')
    return re.findall('\d+.\d+.\d+.\d+', output)


def linux_trace(domain):
    output = subprocess.check_output('traceroute ' + domain + ' -w 1',
                                     shell=True)
    output = output.decode()
    return re.findall('\d+.\d+.\d+.\d+', output)


def get_provider(domain):
    ip = socket.gethostbyname(domain)
    try:
        with urlopen('https://www.whoismyisp.org/ip/' + ip) as page:
            info = page.readall().decode('utf-8')
            return re.search(r'<h1>(.+)</h1>', info).group(1)
    except (URLError, HTTPError):
        return None


def get_country_and_as(info):
    country = re.search(r'country:\s+\w+', info).group(0).split()[-1].upper()
    try:
        origin = re.search(r'(origin|originas):\s+\w+', info).group(0).split()[-1]
    except AttributeError:
        origin = None
    return country, origin


def main():
    domain = sys.argv[1]
    trace = traceroute(domain)
    for ip in trace:
        try:
            country, AS = get_country_and_as(whois(ip))
            provider = get_provider(ip)
            if AS is not None:
                print('%s\t\tCountry: %s\tAS: %s\tProvider: %s' % (ip, country, AS, provider))
            else:
                print('%s\t\tCountry: %s\tProvider: %s' % (ip, country, provider))
        except WhoIsError:
            print('%s is reserved address' % ip)


if __name__ == '__main__':
    main()

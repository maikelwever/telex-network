from dns import resolver
from telex import plugin

import socket


class NetworkPlugin(plugin.TelexPlugin):
    """
    Network plugin for Telex bot.

    """

    PING_TIMEOUT = 1000
    PING_EXCLUSIONS = ['10.', '172.', '192.']

    HOSTNAME_REGEX = "^(?P<hostname>([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*" + \
                     "[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    IP4_REGEX = "^(?P<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)" + \
                "{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$"

    usage = [
        "!dns [domainname]: Query the A record for 'domainname'",
        "!dns [recordtype] [domainname]: Query the 'recordtype' record for 'domainname'",
        "!dns [ipv4_address]: Query the reverse dns for 'ipv4_address'",
        # "!ping [destination]: Does a ping to the destination.",
    ]

    patterns = {
        "^!dns " + HOSTNAME_REGEX: "dns_lookup_a",
        "(?i)^!dns (?P<type>A|AAAA|CNAME|PTR|MX|NS|TXT|SRV|DKIM)" + HOSTNAME_REGEX: "dns_lookup_typed",
        "^!dns " + IP4_REGEX: "dns_lookup_reverse",
    }

    config_options = {
        "ping_timeout": "Timeout in milliseconds for ping."
    }

    def __init__(self, *args, **kwargs):
        super(NetworkPlugin, self).__init__(*args, **kwargs)
        if self.read_option('ping_timeout') and int(self.read_option('ping_timeout')):
            self.PING_TIMEOUT = int(self.read_option('ping_timeout'))

    def dns_lookup(self, msg, domain, recordtype="A"):
        peer = self.bot.get_peer_to_send(msg)
        try:
            result = "\n".join([str(i) for i in resolver.query(domain, recordtype)])
        except resolver.NoAnswer:
            txt = "No answer was given."
            peer.send_msg(txt, reply=msg.id, preview=False)

        peer.send_msg(result, reply=msg.id, preview=False)

    def dns_lookup_a(self, msg, matches):
        domain = matches.groupdict()['hostname']
        self.dns_lookup(msg, domain)

    def dns_lookup_typed(self, msg, matches):
        domain = matches.groupdict()['hostname']
        recordtype = matches.groupdict()['type']
        self.dns_lookup(msg, domain, recordtype=recordtype)

    def dns_lookup_reverse(self, msg, matches):
        ip = matches.groupdict()['ip']
        peer = self.bot.get_peer_to_send(msg)

        for exclusion in self.PING_EXCLUSIONS:
            if ip.startswith(exclusion):
                txt = "Error, unknown host"
                peer.send_msg(txt, reply=msg.id, preview=False)

        try:
            result = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, IndexError):
            txt = "Error, unknown host"
            peer.send_msg(txt, reply=msg.id, preview=False)

        peer.send_msg(result, reply=msg.id, preview=False)

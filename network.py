from telex import plugin

import dns.resolver
import socket


class NetworkPlugin(plugin.TelexPlugin):
    """
    Network plugin for Telex bot.

    """

    PING_TIMEOUT = 1000
    PING_EXCLUSIONS = ['10.', '172.', '192.']

    HOSTNAME_REGEX = "(?P<host>([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15})$"
    IP4_REGEX = "(?P<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)" + \
                "{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$"

    usage = [
        "!dns [domainname]: Query the A record for 'domainname'",
        "!dns [recordtype] [domainname]: Query the 'recordtype' record for 'domainname'",
        "!dns [ipv4_address]: Query the reverse dns for 'ipv4_address'",
        # "!ping [destination]: Does a ping to the destination.",
    ]

    patterns = {
        "^!dns " + HOSTNAME_REGEX: "dns_lookup_a",
        "^!dns (?P<type>\w+) " + HOSTNAME_REGEX: "dns_lookup_typed",
        "^!dns " + IP4_REGEX: "dns_lookup_reverse",
    }

    config_options = {
        "ping_timeout": "Timeout in milliseconds for ping."
    }

    def dns_lookup(self, msg, domain, recordtype="A"):
        peer = self.bot.get_peer_to_send(msg)
        try:
            result = "\n".join([str(i) for i in dns.resolver.query(domain, recordtype)])
        except dns.resolver.NoAnswer:
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

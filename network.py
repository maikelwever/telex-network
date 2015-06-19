from telex import plugin

import dns.resolver
import socket


class NetworkPlugin(plugin.TelexPlugin):
    """
    Network plugin for Telex bot.

    """

    PING_TIMEOUT = 1000
    PING_EXCLUSIONS = ['10.', '172.', '192.']

    usage = [
        "!dns [recordtype] [domainname]: Query the 'recordtype' record for 'domainname'",
        "!dns [ipv4_address]: Query the reverse dns for 'ipv4_address'",
        # "!ping [destination]: Does a ping to the destination.",
    ]

    patterns = {
        "^!dns (?P<host>([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15})$": "dns_lookup_a",
        "^!dns (?P<record>\w+) (?P<host>([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15})$": "dns_lookup_typed",
        "^!dns (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$": "dns_lookup_reverse",
    }

    config_options = {
        "ping_timeout": "Timeout in milliseconds for ping."
    }

    def dns_lookup_a(self, msg, matches):
        domain = matches.groupdict()['host']
        self.dns_lookup(msg, domain)

    def dns_lookup_typed(self, msg, matches):
        domain = matches.groupdict()['host']
        recordtype = matches.groupdict()['record']
        self.dns_lookup(msg, domain, recordtype=recordtype)

    def dns_lookup(self, msg, domain, recordtype="A"):
        peer = self.bot.get_peer_to_send(msg)

        try:
            result = "\n".join([str(i) for i in dns.resolver.query(domain, recordtype)])
        except Exception as e:
            txt = "Error: {0}".format(str(e))
            peer.send_msg(txt, reply=msg.id, preview=False)
            return

        peer.send_msg(result, reply=msg.id, preview=False)

    def dns_lookup_reverse(self, msg, matches):
        ip = matches.groupdict()['ip']
        peer = self.bot.get_peer_to_send(msg)

        for exclusion in self.PING_EXCLUSIONS:
            if ip.startswith(exclusion):
                txt = "Error, unknown host"
                peer.send_msg(txt, reply=msg.id, preview=False)
                return

        try:
            result = socket.gethostbyaddr(ip)[0]
        except:
            txt = "Error, unknown host"
            peer.send_msg(txt, reply=msg.id, preview=False)
            return

        peer.send_msg(result, reply=msg.id, preview=False)

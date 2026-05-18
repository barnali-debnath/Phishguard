import dns.resolver
import tldextract

def dns_lookup(url):

    ext = tldextract.extract(url)

    domain = ext.domain + '.' + ext.suffix

    try:

        result = dns.resolver.resolve(
            domain,
            'A'
        )

        ips = []

        for ip in result:

            ips.append(ip.to_text())

        return ips

    except:

        return []
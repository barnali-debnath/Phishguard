import whois
import tldextract

from datetime import datetime

def whois_lookup(url):

    ext = tldextract.extract(url)

    domain = ext.domain + '.' + ext.suffix

    try:

        info = whois.whois(domain)

        creation_date = info.creation_date
        expiration_date = info.expiration_date

        if isinstance(creation_date, list):
            creation_date = min(creation_date)

        if isinstance(expiration_date, list):
            expiration_date = max(expiration_date)

        age_days = None

        if creation_date:

            today = datetime.now().astimezone()

            age_days = (
                today - creation_date
            ).days

        return {

            "creation_date":
            creation_date,

            "expiration_date":
            expiration_date,

            "age_days":
            age_days
        }

    except:

        return {}
from urllib.parse import unquote

def decode_url(url):

    decoded_url = unquote(url)

    return decoded_url
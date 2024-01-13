from urllib.parse import urlparse
import re
import ipaddress
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
import requests
from datetime import datetime

# 3.1. Address Bar Based Features
# 1. Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2. Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

# 3. Checks the presence of @ in URL (Have_At_Sign)
def haveAtSign(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at

# 4. Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    if len(url) < 54:
        length = 0
    else:
        length = 1
    return length

# 5. Gives the number of '/' in URL (URL_Depth)
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth

# 6. Checking for redirection '//' in the url (Redirection)
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0

# 7. Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"

    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0

# 9. Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate

# 3.2. Domain Based Features
# 11. DNS Record availability (DNS_Record)
def dns_record(url):
    try:
        domain_name = whois.whois(url)
        return 0
    except:
        return 1

# 12. Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        response = urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read()
        rank = BeautifulSoup(response, "xml").find("REACH")
        if rank is not None:
            rank = int(rank['RANK'])
        else:
            return 1  # Assuming an error indicates potential phishing
    except (urllib.error.URLError, ValueError, TypeError) as e:
        # Handle specific errors and log them if needed
        print(f"Error: {e}")
        return 1  # Assuming an error indicates potential phishing

    if rank < 100000:
        return 1
    else:
        return 0

# 13. Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domain_age(url):
    try:
        domain_name = whois.whois(url)
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
            try:
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain / 30) < 6):
                age = 1
            else:
                age = 0
        return age
    except:
        return 1

# 14. End time of domain: The difference between termination time and current time (Domain_End)
def domain_end(url):
    try:
        domain_name = whois.whois(url)
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if ((end / 30) < 6):
                end = 0
            else:
                end = 1
        return end
    except:
        return 1

# 3.3. HTML and JavaScript based Features
# 15. IFrame Redirection (iFrame)
def iframe_redirection(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1

# 16. Checks the effect of mouse over on status bar (Mouse_Over)
def status_bar_customization(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0

# 17. Checks the status of the right click attribute (Right_Click)
def disabling_right_click(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1

# 18. Checks the number of forwardings (Web_Forwards)
def website_forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1

# Function to extract features
def feature_extraction(url):
    features = []

    # Address bar based features (9)
    features.append(getDomain(url))
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # Domain based features (4)
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    features.append(dns_record(urlparse(url).netloc))
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domain_age(urlparse(url).netloc))
    features.append(1 if dns == 1 else domain_end(urlparse(url).netloc))

    # HTML & Javascript based features (4)
    try:
        response = requests.get(url)
    except:
        response = ""
    features.append(iframe_redirection(response))
    features.append(status_bar_customization(response))
    features.append(disabling_right_click(response))
    features.append(website_forwarding(response))

    return features

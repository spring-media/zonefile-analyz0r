import requests
import sys
import csv as csv_output
import urllib3
import socket
import dns.resolver
from dns.rdatatype import *
from sty import fg, rs

if len(sys.argv) is not 4:
    print('''{}Usage: python {} [FILE] [MY_DOMAIN] [FORMAT]{}
    [FILE] zone file
    [MY_DOMAIN] treat this domain as 1st party
    [FORMAT] console | csv (default console)
    '''.format(fg.red, sys.argv[0], fg.rs))
    
    exit(-1)

TIMEOUT = 5.0
DEBUG = False
MY_DOMAIN = sys.argv[2]
FORMAT = "console" if sys.argv[3] not in ("console", "csv") else sys.argv[3]

# output_result = getattr(, sys.argv[3])
def check(proto, domain):
    if DEBUG:
        print('Checking {}'.format('{}://{}'.format(proto, domain)))
    checks = list()
    http_check = check_url('{}://{}'.format(proto, domain))
    checks.append(http_check)
    # follow redirects, step by step
    depth = 0
    while http_check['code'] not in ['SSL', 'LOOP', 'ERR', 'TIME'] and http_check['code'] >= 300 and http_check['code'] < 400:
        if DEBUG:
            print('{}Following redirect to {}.{}'.format(fg.red, http_check['url'], fg.rs))
        depth += 1
        if depth > 5:
            print('{}Error: check resulted in too many redirects "{}"{}'.format(fg.red, http_check['url'], fg.rs))
            break
        http_check = check_url(http_check['url'])
        checks.append(http_check)
    return checks

def check_url(url):
    try:
        res = requests.get(url, allow_redirects=False, timeout=TIMEOUT)
        if res.status_code >= 300 and res.status_code < 400:
            return {'code': res.status_code, 'url': res.headers['Location']}
        else:
            return {'code': res.status_code, 'url': res.url}
    except requests.exceptions.Timeout:
        return {'code': 'TIME', 'url': f'timeout after {TIMEOUT} seconds'}
    except requests.exceptions.SSLError:

        # print(e.args[0].reason)
        # print(type(e.args[0].reason).__name__)
        # print('vars')
        # print(vars(e.args[0]))
        return {'code': 'SSL'} #{e.args[0].reason}'}
    except requests.exceptions.TooManyRedirects:
        return {'code': 'LOOP'}
    except:
        # print(sys.exc_info()[0], end='')
        return {'code': 'ERR', 'url': f'error {sys.exc_info()[0].__name__}'}


def format_code(checks):
    out = ""
    for check in checks:
        code = check['code']    
        if type(code) is str:
            out += ' [{}{}{}]'.format(fg.red, code, fg.rs)
        elif 200 == code:
            out += ' [{}{}{}]'.format(fg.green, code, fg.rs)
        elif code >= 300 and code < 400:
            if not MY_DOMAIN in check['url']:
                color = fg.red
            else:
                color = fg.green
            target = ' -> {}{}{}'.format(color, check['url'], fg.rs)
            out += ' [{}{}{}]'.format(fg.li_black, code, fg.rs) + target
        elif code >= 400 and code < 500:
            out += ' [{}{}{}]'.format(fg.yellow, code, fg.rs)
        else:
            out += ' [{}{}{}]'.format(fg.red, code, fg.rs)
    return out


def read_zonefile():
    '''
        read zonefile from disk, removing duplicate entries
    '''
    entries = list()
    seen = set()
    filename = sys.argv[1]
    if DEBUG:
        print('{}Reading Zone file from {}.{}'.format(fg.green, filename, fg.rs))

    with open(filename) as f:
        for line in f.readlines():
            s = list(filter(lambda x: x != '', line.split()))            
            
            if not len(s) == 5 or s[3] not in ('CNAME', 'A'):
                continue

            # strip the '.' at end
            entry = {'domain':s[0][:-1], 'type':s[3]}
            domain = entry['domain']
            if domain not in seen:
                seen.add(domain)
                entries.append(entry)
            
            if DEBUG:
                print(f'testing {entry}')
    return entries

def classify_dns_entry(entry):
    '''
    try to classify the DNS entry

    -> 1st party
    -> 3rd party
    -> DNS Error
    '''
    domain = entry['domain']
    typ = entry['type']
    try: 
        for rdataset in dns.resolver.query(domain, typ):
            
            if rdataset.rdtype == CNAME:
                target = rdataset.target.to_text(omit_final_dot=True)
                
                if DEBUG:
                    print('{} is aliased to {}'.format(domain, target))
                
                if MY_DOMAIN in target:
                    return {'entry': entry, 'status': 'ok', 'type': '1st party', 'target': target}
                else:
                    return {'entry': entry, 'status': 'ok', 'type': '3rd party', 'target': target}
            if rdataset.rdtype == A:
                if DEBUG:
                    print('{} resolved to address {}'.format(domain, rdataset.address))
                return {'entry': entry, 'status': 'ok', 'type': 'A'}
            
    except dns.resolver.NXDOMAIN:
        if DEBUG:
            print("No such domain {}".format(domain))
        return {'entry': entry, 'status': 'nok', 'type': 'DNS ERROR', 'target': domain}
    except dns.resolver.NoAnswer:
        return {'entry': entry, 'status': 'nok', 'type': 'DNS ERROR', 'target': domain}
    except dns.resolver.NoNameservers:
        return {'entry': entry, 'status': 'nok', 'type': 'DNS ERROR', 'target': domain}
    except:
        print(f'unhandled error {sys.exc_info()[0].__name__}')

def is_check_not_decent(check):
    error_codes = ['SSL', 'LOOP', 'ERR', 'TIME']

    return check['http_check'][-1]['code'] in error_codes or check['https_check'][-1]['code'] in error_codes

def csv(output):
    with open('check.csv', mode='w') as check_file:
        writer = csv_output.writer(check_file, delimiter=',', quotechar='"', quoting=csv_output.QUOTE_MINIMAL)
        writer.writerow(['Domain', 'Target', 'Http_Check', 'Https_Check'])

        for i in list(filter(lambda x: x['classification']['status'] == 'ok' and is_check_not_decent(x), output)):
            writer.writerow([
                i['classification']['entry']['domain'], 
                i['classification'].get("target", "IP"), 
                i['http_check'][-1]['code'], 
                i['https_check'][-1]['code']
            ])

def console(output):
    failed = list(filter(lambda x: x['classification']['status'] == 'nok', output))
    if len(failed) > 0:
        print("{}Failures:{}                         ".format(fg.red, fg.rs))

    for i in failed:
        print("{} reason: {}".format(i['classification']['target'], i['classification']['type']))

    first_party = list(filter(lambda x: x['classification']['type'] == '1st party', output))
    if len(first_party) > 0:
        print("{}[CNAME] Probably First Party:{}".format(fg.green, fg.rs))
        
        for i in first_party:
            print('{} -> {}\n{}\n'.format(i['classification']['entry']['domain'], i['classification']['target'], i['pretty']))

    third_party = list(filter(lambda x: x['classification']['type'] == '3rd party', output))
    if len(third_party) > 0:
        print("{}[CNAME] Probably 3rd Party:{}".format(fg.yellow, fg.rs))

        for i in third_party:
            print('{} -> {}\n{}\n'.format(i['classification']['entry']['domain'], i['classification']['target'], i['pretty']))

    probably_ok = list(filter(lambda x: x['classification']['type'] == 'A', output))
    if len(probably_ok) > 0:
        print("{}A records:{}".format(fg.da_cyan, fg.rs))
        
        for i in probably_ok:
            print('{}\n{}\n'.format(i['classification']['entry']['domain'], i['pretty']))

# domains = read_zonefile()

# if False:
if DEBUG:
    entries = list()
    # this is no longer registered
    entries.append( {'domain':'sterne-1.welt.de', 'type': 'A'} )
    # all ok
    entries.append( {'domain':'www.welt.de', 'type': 'A'} )
    # broken CNAME
    entries.append( {'domain':'aktion.welt.de', 'type': 'CNAME'} )
    # redirect
    entries.append( {'domain':'bmw.welt.de', 'type': 'CNAME'} )
    entries.append( {'domain':'amp.welt.de', 'type': 'CNAME'} )
    entries.append( {'domain':'www.beste.welt.de', 'type': 'CNAME'} )
else:
    entries = read_zonefile()

output = list()
output_result = locals()[FORMAT]
cnt = 0

for entry in entries:
    cnt += 1
    print('Processing {}/{}                   '.format(cnt, len(entries)), end='\r')
    
    classification = classify_dns_entry(entry)
    if DEBUG and cnt == 20:
       break
       
    if classification['status'] == 'ok':

        domain = entry['domain']

        http_checks = check('http', domain)
        https_checks = check('https', domain)
        
        output.append({
            'classification': classification,
            'http_check': http_checks,
            'https_check': https_checks,
            'pretty': 'HTTP {}\nHTTPS{}'.format(format_code(http_checks), format_code(https_checks))
        })
    else: 
        output.append({
            'classification': classification
        })

output_result(output)

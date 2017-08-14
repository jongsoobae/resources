import os
import sys
import pexpect
import getopt


def usage():
    print 'Usage: create_cert.py domain [-w] [-s|-e] [-d domain1] [-d domain2]'
    print '-w   create wildcard cert for domain.'
    print '-s   SHA1 alrorithm select'
    print '-e   ECC alrorithm select'
    print 'without "-s|-e" option is SHA2 alrorithm'
    print '-d   create multidomain cert'
    sys.exit(1)


def main(domain, argv):
    if domain == '-h':
        usage()

    opts = []
    try:
        opts, args = getopt.getopt(argv, 'hwsed:')
    except getopt.GetoptError:
        print '??'
        usage()

    is_wildcard = False
    is_sha2 = True
    is_ecc = False
    mdc_domains = []
    mdc_index = 1
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt == '-w':
            is_wildcard = True
        elif opt == '-s':
            print 'SAH1 alrorithm selected'
            is_sha2 = False
            is_ecc = False
        elif opt == '-e':
            print 'ECC alrorithm selected'
            is_sha2 = False
            is_ecc = True
        elif opt == '-d':
            mdc_domains.append('DNS.%s = %s\n' % (str(mdc_index), arg))
            mdc_index += 1

    if mdc_index > 1:
        do_create_mdc(domain, is_wildcard, is_sha2, is_ecc, mdc_domains)
    else:
        do_create_cert(domain, is_wildcard, is_sha2, is_ecc)

    command1 = 'openssl x509 -in %s/%s.crt -noout -text' % (domain, domain)
    print(pexpect.run(command1))



def do_create_cert(domain, is_wildcard, is_sha2, is_ecc):
    create_key(domain, is_ecc)
    create_csr(domain, is_wildcard, is_sha2, is_ecc)
    create_crt(domain, is_sha2, is_ecc)
    create_directory(domain)
    move_files_to_directory(domain)


def do_create_mdc(domain, is_wildcard, is_sha2, is_ecc, mdc_domains):
    create_mdc_conf(domain, mdc_domains)
    create_key(domain, is_ecc)
    create_csr_for_mdc(domain, is_wildcard, is_sha2, is_ecc)
    create_crt_for_mdc(domain, is_sha2, is_ecc)
    create_directory(domain)
    move_files_to_directory(domain)


def read_mdc_conf():
    with open('mdccert.cnf', 'r') as sample_file:
        for line in sample_file:
            yield line


def create_mdc_conf(domain, mdc_domains):
    with open('%s.cnf' % domain, 'w') as output_file:
        for line in read_mdc_conf():
            output_file.write(line)
            if '[ alt_names ]' in line:
                output_file.writelines(mdc_domains)


def create_key(domain, is_ecc):
    if is_ecc == True:
        command = 'openssl ecparam -out %s.key -name prime256v1 -genkey' % domain
    else:
        command = 'openssl genrsa -out %s.key 1024' % domain
    pexpect.run(command)


def create_csr_for_mdc(domain, is_wildcard, is_sha2, is_ecc):
    if is_sha2 == True:
        command = 'openssl req -new -key %s.key -out %s.csr -config %s.cnf' % (domain, domain, domain)
    elif is_ecc == True:
        command = 'openssl req -new -key %s.key -out %s.csr -config %s.cnf -sha512' % (domain, domain, domain)
    else:
        command = 'openssl req -sha1 -new -key %s.key -out %s.csr -config %s.cnf' % (domain, domain, domain)
    child = pexpect.spawn(command)
    child.expect('Country')
    child.sendline('KR')
    child.expect('State')
    child.sendline('Seoul')
    child.expect('Locality')
    child.sendline('Kangnam')
    child.expect('Organization Name')
    child.sendline('CDNetworks')
    child.expect('Organizational Unit Name')
    child.sendline('qateam')
    child.expect('Common Name')
    if is_wildcard:
        child.sendline('*.%s' % domain)
    else:
        child.sendline(domain)
    child.expect('Email Address')
    child.sendline('wonsung.kang@cdnetworks.com')
    child.expect('A challenge')
    child.sendline('')
    child.expect('An optional company name')
    child.sendline('')

    command1 = 'openssl req -in %s.csr -noout -text' % domain
    pexpect.run(command1)


def create_csr(domain, is_wildcard, is_sha2, is_ecc):
    if is_sha2 == True:
        command = 'openssl req -new -key %s.key -out %s.csr' % (domain, domain)
    elif is_ecc == True:
        command = 'openssl req -new -key %s.key -out %s.csr -sha512' % (domain, domain)
    else:
        command = 'openssl req -sha1 -new -key %s.key -out %s.csr' % (domain, domain)
    child = pexpect.spawn(command)
    child.expect('Country')
    child.sendline('KR')
    child.expect('State')
    child.sendline('Seoul')
    child.expect('Locality')
    child.sendline('Kangnam')
    child.expect('Organization Name')
    child.sendline('CDNetworks')
    child.expect('Organizational Unit Name')
    child.sendline('qateam')
    child.expect('Common Name')
    if is_wildcard:
        child.sendline('*.%s' % domain)
    else:
        child.sendline(domain)
    child.expect('Email Address')
    child.sendline('wonsung.kang@cdnetworks.com')
    child.expect('A challenge')
    child.sendline('')
    child.expect('An optional company name')
    child.sendline('')

    try:
        child.interact()
    except (Exception, ):
        pass


def create_crt(domain, is_sha2, is_ecc):
    if is_sha2 == True:
        command = 'openssl x509 -req -days 3650 -in %s.csr -signkey %s.key -out %s.crt' % (domain, domain, domain)
    elif is_ecc == True:
        command = 'openssl x509 -req -days 3650 -in %s.csr -signkey %s.key -out %s.crt -sha512' % (domain, domain, domain)
    else:
        command = 'openssl x509 -req -sha1 -days 3650 -in %s.csr -signkey %s.key -out %s.crt' % (domain, domain, domain)
    pexpect.run(command)


def create_crt_for_mdc(domain, is_sha2, is_ecc):
    if is_sha2 == True:
        command = 'openssl x509 -req -days 365 -in %s.csr -signkey %s.key -out %s.crt -extensions v3_req -extfile %s.cnf' %(domain, domain, domain, domain)
    elif is_ecc == True:
        command = 'openssl x509 -req -days 365 -in %s.csr -signkey %s.key -out %s.crt -extensions v3_req -extfile %s.cnf -sha512' % (domain, domain, domain, domain)
    else:
        command = 'openssl x509 -req -sha1 -days 365 -in %s.csr -signkey %s.key -out %s.crt -extensions v3_req -extfile %s.cnf' %(domain, domain, domain, domain)
    print(pexpect.run(command))


def create_directory(domain):
    command = 'mkdir %s' % domain
    pexpect.run(command)


def move_files_to_directory(domain):
    command = 'mv %s.key ./%s' % (domain, domain)
    command2 = 'mv %s.key.org ./%s' % (domain, domain)
    command3 = 'mv %s.crt ./%s' % (domain, domain)
    command4 = 'mv %s.csr ./%s' % (domain, domain)
    pexpect.run(command)
    pexpect.run(command2)
    pexpect.run(command3)
    pexpect.run(command4)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1], sys.argv[2:])
    else:
        usage()

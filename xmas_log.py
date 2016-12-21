#!/usr/bin/python
def get_import_error_message(library):
    return library + ' module not installed, try:\r\npip install ' + library


try:
    import sys
except Exception as e:
    print(get_import_error_message('sys'))
    raise SystemExit

try:
    import os
except Exception as e:
    print(get_import_error_message('os'))
    raise SystemExit

try:
    import re
except Exception as e:
    print(get_import_error_message('re'))
    raise SystemExit

try:
    import smtplib
except Exception as e:
    print(get_import_error_message('smtplib'))
    raise SystemExit

try:
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
except Exception as e:
    print(get_import_error_message('email'))
    raise SystemExit

try:
    import socket
except Exception as e:
    print(get_import_error_message('socket'))
    raise SystemExit

try:
    import datetime
except Exception as e:
    print(get_import_error_message('datetime'))
    raise SystemExit

try:
    import argparse
except Exception as e:
    print(get_import_error_message('argparse'))
    raise SystemExit

# globals
state_file = 'xmas_state.txt'
regex_capture = '([(\d\.)]+) - - \[(.*?)\]\s(\".*?\")\s\d\d\d\s([0-9]{1,})'

# config items
'''
Edit start here
'''

'''
The recipients list is either a single value such as below
or a list object that is commented out below.  If configuring
a list of email addresses make sure to comment out the single
string value
'''
recipient = 'afernan4e@gmail.com'

# recipient = ['foo@foo.com', 'otherfoo@foo.com']

'''
Configure to point to an absolute path to your apache access
logs such as /var/log/apache2/access.log.
'''
# log_path = '/var/log/apache2/access.log'
log_path = 'localhost_access_log.2016-12-19.txt'

'''
Configure threshold for ban in MegaBytes.  Default is 10MB,
that might be too low, YMMV.
'''
threshold_in_mb = 10
threshold_in_bytes = threshold_in_mb * 1024 * 1024
'''
Edit end here
'''


def main():
    parser = argparse.ArgumentParser(
        description='Iterates over apache logs and calculates bytes transferred per host, if bytes goes over '
                    'threshold the IP is banned')

    parser.add_argument('-d', dest='debug', action='store_false', required=False, default=True,
                        help="Print IP's to be banned and MB values, won't update " + state_file + " file")
    parser.add_argument('-e', dest='email', action='store_false', required=False, default=True,
                        help="Don't send email, won't update " + state_file + " file")
    parser.add_argument('-hd', dest='hosts', action='store_false', required=False, default=True,
                        help="Don't append to /etc/hosts.deny, won't update " + state_file + " file")

    cli_options = parser.parse_args()

    # get the ip bytes dictionary based on the contents of the log file
    ip_bytes_dict = get_ip_bytes_dict()

    # read the banned ip log file
    banned_ip = get_banned_ips()

    # go through ips and byte counts and determine if we should take action
    for ip, num_bytes in ip_bytes_dict.iteritems():
        # skip this ip if it's under the threshold or it's already banned
        if (num_bytes < threshold_in_bytes) or (ip in banned_ip):
            continue

        '''
        No changes will be written to the state file if debug,
        no email or update hosts.deny argument is passed.  These
        arguments are generally for seeing what would happen should
        you run it live
        '''
        if cli_options.debug:
            if cli_options.hosts:
                update_hosts_deny(ip)
            if cli_options.email:
                email_admin(ip)
            # if not cli_options.hosts and not cli_options.email:
            # todo do something
            update_state_file(ip)
        else:
            mb = num_bytes / (1024 * 1024)
            print('IP ' + str(ip) + ' would have been banned for using ' + str(mb) + 'MB')


def update_state_file(ip):
    with open(os.getcwd() + '/' + state_file, 'a') as xmas_state_file:
        xmas_state_file.write(ip + '\r\n')


def get_banned_ips():
    banned_ip = []

    try:
        with open(os.getcwd() + '/' + state_file, 'r+') as log_file:
            banned_ip = log_file.read().splitlines()
    except IOError:
        open(os.getcwd() + '/' + state_file, 'a').close()

    return banned_ip


def get_ip_bytes_dict():
    bytes_dict = {}

    with open(log_path, 'r') as log_file:
        for line in iter(log_file):
            try:
                ip, dtg, m_url, size = parse_log_line(line)

                if ip in bytes_dict:
                    bytes_dict[ip] += int(size)
                else:
                    bytes_dict[ip] = int(size)
            except ValueError:
                pass

    return bytes_dict


def update_hosts_deny(ip):
    try:
        # file = open('/etc/hosts.deny', 'a')
        hosts_file = open('hosts.deny', 'a')
        hosts_file.write(ip + '\n')
        hosts_file.close()
    except IOError:
        print('Did you forget to run me as root or another privileged user that can write to /etc/hosts.deny?')
        raise SystemExit


def email_admin(ip):
    # Construct the MIME multipart stuff
    message = MIMEMultipart()

    message['Subject'] = 'New IP Above Configured Threshold ' + str(ip)
    message['From'] = 'root@christmasinfairbanks.com'
    message['To'] = ', '.join(recipient)

    try:
        # Send the email
        smtplib.SMTP('localhost').sendmail('root@christmasinfairbanks.com', recipient, message.as_string())

        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + " Successfully sent email to the Admin for ip=" + ip)
    except (smtplib.SMTPHeloError,
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
            smtplib.SMTPDataError,
            socket.error) as exc:
        print(datetime.datetime.now()
              .strftime("%Y-%m-%d %H:%M") + " Sending email failed for ip=" + ip + " exception " + str(exc))


def parse_log_line(line):
    try:
        matches = re.findall(regex_capture, line)

        ip = matches[0][0].strip()
        dtg = matches[0][1].strip()
        m_url = matches[0][2].strip()
        size = matches[0][3].strip()

        return ip, dtg, m_url, size
    except:
        raise ValueError('Error parsing log line')


if __name__ == '__main__':
    main()

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
    from email.MIMEMultipart import MIMEMultipart
    from email.MIMEBase import MIMEBase
    from email import Encoders
except Exception as e:
    print(get_import_error_message('email'))
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


def main():
    parser = argparse.ArgumentParser(
        description='Iterates over apache logs and calculates bytes transferred per host, if bytes goes over '
                    'threshold the IP is banned')

    parser.add_argument('-d', dest='debug', action='store_false', required=False, default=True,
                        help="Print IP's to be banned and MB values, won't update .xmas_state file")
    parser.add_argument('-e', dest='email', action='store_false', required=False, default=True,
                        help="Don't send email, won't update .xmas_state file")
    parser.add_argument('-hd', dest='hosts', action='store_false', required=False, default=True,
                        help="Don't append to /etc/hosts.deny, won't update .xmas_state file")

    args = parser.parse_args()
    '''
    Edit start here
    '''

    '''
    The recipients list is either a single value such as below
    or a list object that is commented out below.  If configuring
    a list of email addresses make sure to comment out the single
    string vlaue
    '''
    recipient = 'foo@foo.com'

    # recipient = ['foo@foo.com', 'otherfoo@foo.com']

    '''
    Configure to point to an absolute path to your apache access
    logs such as /var/log/apache2/access.log.
    '''
    # log_path = '/var/log/apache2/access.log'
    log_path = '/home/erik/xmas/fb/localhost_access_log.2016-12-19.txt'

    '''
    Configure threshold for ban in MegaBytes.  Default is 10MB,
    that might be too low, YMMV.
    '''
    threshold_in_mb = 10
    '''
    Edit end here
    '''
    threshold_in_bytes = threshold_in_mb * 1024 * 1024

    regex_capture = '([(\d\.)]+) - - \[(.*?)\]\s(\".*?\")\s\d\d\d\s([0-9]{1,})'

    # update the bytes dictionary based on the contents of the log file
    bytes_dict = {}
    with open(log_path, 'r') as log_file:
        for line in iter(log_file):
            try:
                ip, dtg, m_url, size = parse_log_line(line, regex_capture)

                if ip in bytes_dict:
                    bytes_dict[ip] += int(size)
                else:
                    bytes_dict[ip] = int(size)
            except ValueError:
                pass

    # read the banned ip log file
    banned_ip = []
    try:
        with open(os.getcwd() + '/.xmas_state', 'r+') as log_file:
            banned_ip = log_file.read().splitlines()
    except IOError:
        open(os.getcwd() + '/.xmas_state', 'a').close()

    # go through ips and byte counts and deteremine if we should take action
    # todo: i'm getting an unresolved attribute reference on iteritems
    for ip, b_size in bytes_dict.iteritems():
        # keep going if this is under the threshold
        if b_size < threshold_in_bytes:
            continue

        # nothing to do, this ip is already banned
        if ip in banned_ip:
            continue

        '''
        No changes will be written to the state file if debug,
        no email or update hosts.deny argument is passed.  These
        arguments are generally for seeing what would happen should
        you run it live
        '''
        if args.debug:
            if args.hosts:
                update_hosts_deny(ip)
            if args.email:
                email_admin(recipient, ip)
            if not args.hosts and not args.email:
                with open(os.getcwd() + '/.xmas_state', 'a') as xmas_state_file:
                    xmas_state_file.write(ip + '\r\n')
        else:
            mb = b_size / (1024 * 1024)
            print('IP ' + str(ip) + ' would have been banned for using ' + str(mb) + 'MB')


def update_hosts_deny(ip):
    try:
        file = open('/etc/hosts.deny', 'a')
        file.write(ip + '\n')
        file.close()
    except IOError:
        print('Did you forget to run me as root or another privileged user that can write to /etc/hosts.deny?')
        raise SystemExit


def email_admin(recipient, ip):
    # Construct the MIME multipart stuff
    message = MIMEMultipart()

    message['Subject'] = 'New IP Above Configured Threshold ' + str(ip)
    message['From'] = 'root@christmasinfairbanks.com'
    message['To'] = ', '.join(recipient)

    try:
        # Send the email
        smtplib.SMTP('localhost').sendmail('root@christmasinfairbanks.com', recipient, message.as_string())

        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + " Successfully sent email to the Admin")
    except (smtplib.SMTPHeloError,
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
            smtplib.SMTPDataError,
            smtplib.SMTPNotSupportedError) as e:
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + " Sending email failed " % e)


def parse_log_line(line, regex_capture):
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

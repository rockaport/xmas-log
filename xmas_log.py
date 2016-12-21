#!/usr/bin/python
try:
  import sys
except:
  print 'sys module not installed, try:\r\npip install sys'
  raise SystemExit

try:
  import os
except:
  print 'os module not installed, try:\r\npip install os'
  raise SystemExit

try:
  import re
except:
  print 're module not installed, try:\r\npip install re'
  raise SystemExit

try:
  import smtplib
except:
  print 'smtplib module not installed, try:\r\npip install smtplib'
  raise SystemExit

try:
  from email.MIMEMultipart import MIMEMultipart
  from email.MIMEBase import MIMEBase
  from email import Encoders
except:
  print 'email module not installed, try:\r\npip install email'
  raise SystemExit

try:
  import datetime
except:
  print 'datetime module not installed, try:\r\npip install datetime'
  raise SystemExit

try:
  import argparse
except:
  print 'argparse module not installed, try:\r\npip install argparse'
  raise SystemExit


def main():

  parser = argparse.ArgumentParser(description='Iterates over apache logs and calculates bytes transferred per host, if bytes goes over threshold the IP is banned')
  parser.add_argument( '-d', dest='debug', action='store_false', required=False, default=True, help="Print IP's to be banned and MB values, won't update .xmas_state file")
  parser.add_argument( '-e', dest='email', action='store_false', required=False, default=True, help="Don't send email, won't update .xmas_state file")
  parser.add_argument('-hd', dest='hosts', action='store_false', required=False, default=True, help="Don't append to /etc/hosts.deny, won't update .xmas_state file")

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

  #recipient = ['foo@foo.com', 'otherfoo@foo.com']

  '''
  Configure to point to an absolute path to your apache access
  logs such as /var/log/apache2/access.log.  
  '''
  #log_path = '/var/log/apache2/access.log'
  log_path = '/home/erik/xmas/fb/localhost_access_log.2016-12-19.txt'

  '''
  Configure threshold for ban in MegaBytes.  Default is 10MB,
  that might be too low, YMMV.
  '''
  threshold_MB = 10
  '''
  Edit end here
  '''
  thresh = threshold_MB * 1024 * 1024

  cwd = os.getcwd()
  
  f = open(log_path, 'r')

  bytes_dict = {}

  regex_capture = '([(\d\.)]+) - - \[(.*?)\]\s(\".*?\")\s\d\d\d\s([0-9]{1,})'
  
  for line in iter(f):
    ip, dtg, m_url, size = ParseLogLine(line, regex_capture)
    if ip != False and dtg != False and size != False:
      if ip in bytes_dict:
        bytes_dict[ip] += int(size)
      else:
        bytes_dict[ip] = int(size)

  f.close()

  try:
    with open(cwd + '/.xmas_state', 'r+') as f:
      banned_ip = f.read().splitlines()
  except IOError:
    open(cwd + '/.xmas_state', 'a').close()
    banned_ip = []
    
  f = open(cwd + '/.xmas_state', 'a')

  for ip, b_size in bytes_dict.iteritems():
    if b_size > thresh:
      if ip not in banned_ip:
        '''
        No changes will be written to the state file if debug, 
        no email or update hosts.deny argument is passed.  These
        arguments are generally for seeing what would happen should
        you run it live
        '''
        if args.debug:
          if args.hosts:
            UpdateHostsDeny(ip)
          if args.email:
            EmailAdmin(recipient, ip) 
          if not args.hosts and not args.email:
            f.write(ip + '\r\n')
        else:
          mb = ((b_size / 1024) / 1024)
          print 'IP ' + str(ip) + ' would have been banned for using ' + str(mb) + 'MB'
  f.close()

def UpdateHostsDeny(ip):
  try:
    f = open('/etc/hosts.deny', 'a')
    f.write(ip + '\n')
    f.close()
  except IOError:
    print 'Did you forget to run me as root or another priveleged user that can write to /etc/hosts.deny?'
    raise SystemExit

def EmailAdmin(recipient, ip):
  email_to = recipient
  msg = MIMEMultipart()
  msg['Subject'] = 'New IP Above Configured Threshold ' + str(ip)
  msg['From'] = 'root@christmasinfairbanks.com'
  msg['To'] = ', '.join(email_to)

  server =  smtplib.SMTP('localhost')
  try:
    server.sendmail('root@christmasinfairbanks.com', email_to, msg.as_string())
    print datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + " Successfully sent email to the Admin"
  except:
    print datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + " Sending email failed"
  
def ParseLogLine(line, regex_capture):
  try:
    matches = re.findall(regex_capture, line)
    ip = matches[0][0].strip()
    dtg = matches[0][1].strip()
    m_url = matches[0][2].strip()
    size = matches[0][3].strip()
  except:
    return False, False, False, False

  return ip, dtg, m_url, size

if __name__ == '__main__':
  main()

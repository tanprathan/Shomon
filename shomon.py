#!/usr/bin/env python

# Initialize Shodan
import shodan
import smtplib

shomon_txt = """
+++++++++++++++++++++++++++++++++++++++++++
 _______ __           _______              
|     __|  |--.-----.|   |   |.-----.-----.
|__     |     |  _  ||       ||  _  |     |
|_______|__|__|_____||__|_|__||_____|__|__|

                  Shodan Firehose Alert 0.5
+++++++++++++++++++++++++++++++++++++++++++
"""                                          

print shomon_txt

# Shodan API and Private firehose set up

shodan_api = raw_input("Insert Shodan API Key: ")
profile = raw_input("Insert Alert name: ")
host = raw_input("Insert Private Firehose (IP/Network Block): ")
api=shodan.Shodan(shodan_api)
alert=api.create_alert(profile,host)

print "\n"

# Send mail Configuration
def send_mail(from_addr, to_addr_list,
              subject, message,
              login, password,
              smtpserver='mail.smtpxxx.com:25'):
    header  = 'From: %s\n' % from_addr
    header += 'To: %s\n' % ','.join(to_addr_list)
    header += 'Subject: %s\n\n' % subject
    message = header + message
 
    server = smtplib.SMTP(smtpserver)
    server.starttls()
    server.login(login,password)
    problems = server.sendmail(from_addr, to_addr_list, message)
    server.quit()
    return problems

try:
# Subscribe to data for the created alert
	for banner in api.stream.alert(alert['id']):
		print banner
		# Check whether the banner is from ICS service
	        # if 'tags' in banner and 'ics' in banner['tags']:
		send_mail(from_addr = 'Alert@abc.xyz', 
          	to_addr_list = ['networkadmin@abc.xyz'], 
          	subject      = 'Shodan Monitor - '+profile+' - '+host, 
          	message      = 'Your assets in the private firehose has been changed', 
          	login        = 'xxxxxxxxx', 
          	password     = 'xxxxxxxxx')

except:

# Cleanup if any error occurs
	api.delete_alert(alert['id'])

#!/usr/bin/env python


"""Customer Contact Fetcher using the Client Success API
Usage:
  contacts_fetcher.py (-h | --help)
  contacts_fetcher.py service <recipient>
  contacts_fetcher.py privacy <recipient>
  contacts_fetcher.py (-v | --version)

Options:
  -h --help                 Show this screen
  service recipient         Pull list of customers who want service notifications
  privacy recipient         Pull list of customers who want privacy notifications
  -v --version              Show version
"""


""" Customer Contact Fetcher
    This program, when called, and depending upon flags provided
    will call ClientSuccess.com's API and pull the customer
    contacts as required. We use this to keep customers informed of
    maintenance or emergencies. The list is generated in csv format,
    output to the directory defined in the class variable output, then
    emailed to the intended recipient. We use this under Jenkins so it
    can be run as a job by non-tech people or on a schedule.

    There are many verbose print statements to aid in Jenkins console output

    https://help.clientsuccess.com/hc/en-us/articles/360001320332-ClientSuccess-Open-API
"""

import os,sys
import json
import csv
import base64
import subprocess


# // non-standard libraries we should check for
try:
    from urllib2 import Request, urlopen, URLError
    from urllib import urlencode
    from docopt import docopt
except ImportError as e:
    print("Import Error. %s. Try pip install" % e)



class ClientSuccessManager(object):
    """ Handle API requests with the clientsuccess endpoint"""

    # // CLS Vars
    output = '/home/ubuntu/oa/working/clientsuccess/'
    mailer = '/home/ubuntu/oa/oalib/bin/EmailSend.sh'
    subject='List of contacts for '
    workdir='/home/ubuntu/oa/working/clientsuccess/'
    ofile=workdir+'notifications.txt'


    def __init__(self, accessToken, list_type, recipient):
        """ Constructor

	:param accessToken is the temp token issued by Client Success
	:param list_type is either service or gdpr
	:param recipient is the intended email recipient of this report
        """

        self.accessToken = accessToken
        self.request_list = list_type
        self.customerCompanyList = {}
        self.notificationsList = {}
        self.privacyList = {}
        self.recipient = recipient
        self.fetchAllCustomers()
        self.fetchCustomerContacts()


    def urlRequest(self, url, headers=None):
        """ API request handler """

        if headers:
            req = Request(url=url, headers=headers)
        else:
            req = Request(url=url)

        try:
            f = urlopen(req)
        except URLError as e:
            # // provide helpful feedback to Jenkins console if something goes wrong
            if hasattr(e, 'reason'):
                print("Error requesting %s: %s" % (url,e.reason))
            elif hasattr(e, 'code'):
                print("Server Error: %d - %s if using HTTPS could be a cert issue." % (e,code,e.msg))
                print ("Attempted to connect to %s" % url)
            sys.exit(1)

        return(f.read())


    def fetchAllCustomers(self):
        """ This method will fetch a customer list and return customer id's
            that we can operate on later to find contact details, per customer """


        # // Create access headers to work with request
        headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': self.accessToken
                }

        customerListReq = 'https://api.clientsuccess.com/v1/clients?assignedCsmId=&activeOnly='
        headers=headers

        self.customerListReq = self.urlRequest(customerListReq, headers)
        company_list = json.loads(self.customerListReq)

        print("NOTICE: Fetching list of customer id's...")

        # // Build the company customer list
        for company in company_list:
            self.customerCompanyList[company['name']] = company['id']


    def fetchCustomerContacts(self):
        """ This method will fetch all contacts a customer has. Many of these
            include sales, marketing, technical folks and executives. """


        # companyIds = []   # // removed in favor of company list show during exec

        # // Create headers - these may change and be unique to requests
        headers = {
                'content-type' : 'application/json',
                'Accept': 'application/json',
                'Authorization': self.accessToken
                  }

        """
        # // disabling this in favor of  logging company name during execution
        for cid in self.customerCompanyList.values():
            # // filter out any dupes
            if cid not in companyIds:
                cid = str(cid)
                companyIds.append(cid)

        for self.clientId in companyIds:
        """
        for company,clientId in self.customerCompanyList.items():

            print("NOTICE: Fetching customer contacts for %s" % company.encode("utf-8"))	# // helpful output for Jenkins console
            clientId = str(clientId)

            customerContactsReq = 'https://api.clientsuccess.com/v1/clients/'+clientId+'/contacts'

            self.customerContactsReq = self.urlRequest(customerContactsReq, headers)
            contacts_list = json.loads(self.customerContactsReq)

            # // Build the contact list for each company
            for contact in contacts_list:
                if contact['statusId'] == 1:  # // show only active contacts

                    if contact['customFieldValues']:
                        for field in contact['customFieldValues']:
                            if ('service_notifications' in field.values()) and ('true' in field.values()):
                                self.notificationsList[contact['email']] = {contact['name']: contact['id']}
                            if ('gdpr_contact' in field.values()) and ('true' in field.values()):
                                self.privacyList[contact['email']] = {contact['name']: contact['id']}

        # // self.notificationsList contains those who want to be notified of technical issues
        #    self.privacyList contains those who want to be notified of privacy issues

        """  // Debugging

        for k,v in self.notificationsList.items():
            print("Notifications enabled for %s with name and id %s" % (k,v))

        for k,v in self.privacyList.items():
            print("Privacy Notifications enabled for %s with name and id %s" % (k,v))

        """
        print("Creating csv report in %s..." % self.output)	# // helpful output for Jenkins console

	# Create the csv report
        self.createCsvReport()
        if self.createCsvReport:
            self.mailResults()


    def fetchCustomerContactDetails(self):
        """ This method will fetch detailed customer contact
            info and expose those who are on the notify list
            or privacy notifications list. """

        pass


    def mailResults(self):
        """ method to handle sending the final list. We'll reuse the oalib mailer.
            The oalib mailer wants flags passed to it that include:
            $oaBinDir/EmailSend.sh -t ${to} -s "List of contacts for $mode notification" -a $wdir/$outputfile
        """

        # // Build the mail event
        p1 = subprocess.Popen([self.mailer, '-t', self.recipient, '-s', self.subject+self.subject_type, '-a', self.ofile], stdout=subprocess.PIPE)

        if os.path.isfile(self.ofile):

            # // send the mail
            try:
                mailer = p1.communicate()[0]
                print("Mail sent to %s with generated list." % self.recipient)
            except Exception as e:
                print("Error: Error calling EmailSend.sh under mailResults. Error thrown was %s" % e)

        else:
            raise Exception("Error. Unable to locate the csv report located at %s" % self.ofile)



    def createCsvReport(self):
        """ Create a csv report to drop with the requested list.
            We could also take our new data and inject it into a
            sqlite db. """

        final_list = []		# // temp holder for our list

        if self.request_list == 'service':
            self.subject_type = 'service notifications'
            list_to_send = self.notificationsList
            generated_list = 'notifications.txt'

        if self.request_list == 'privacy':
            self.subject_type = 'gdpr notifications'
            list_to_send = self.privacyList
            generated_list = 'privacy.txt'

        # make sure nobody erased our working dir
        if not os.path.isdir(self.output):
            os.mkdir(self.output)
            os.chown(self.output,1000,1000)
            os.chmod(self.output, 0o755)

        # // we could select to include just email address or include name too
        #    but seems we just need email addys as we don't personalize emails
        for email,vals in list_to_send.items():
            for name,id in vals.items():
                #final_list.append([email,name])	# // option to personalize emails
                #final_list.append([email])
                if (email) and ('None' not in email):
                    final_list.append(email)

        # // Append the internal email required
        final_list.append('internal_<email_removed_to_protect_company.com') # // patch 75101

        # // Run a quick sanity check to see if we have anything to write
        #    Our list should number in the hundreds but we'll just check for 100
        final_count = len(final_list)
        if final_count <= 2:	# figure 2 lines could just be error output written from job, which can happen
            sys.exit("Generated list appears to be stunted - invalid. Something went wrong with the pull. \
	              Please check %s" % self.ofile)
        print("The list appears to contain %d email addresses ready to send" % final_count)

        try:
            """
               Patch 75101 send a long str vs a csv so Rackspace can handle the email list format.
               We are removing the csv writer in favor of a str join with space. Leaving previous
               commented out for now.

            """
            #self.csv_header = ['email','name']		# // disable the header
            os.chdir(self.output)                   # // not necessary but Jenkins might be weird
            self.csv_header = ['email']
            #with open(self.output+generated_list, 'wt') as f:
            with open(self.output+generated_list, 'w') as f:
                #csv_writer = csv.writer(f)     # patch 75101 no csv - send txt
                #csv_writer.writerow(self.csv_header)	# // disable header so email sender won't barf
                #for row in final_list:
                #    csv_writer.writerow(row)
                f.write(", ".join([str(i) for i in final_list]))
        except Exception as e:
            # // We need a hard fail here because if we can't write the list, why bother living a lie?
            sys.exit("ERROR: Error writing out csv file. Error thrown was: %s" % e)	# // helpful output for Jenkins console


def clientSuccessAuth():
    """ Set up the api access token  """

    # // yeah not real security but better than creds showing up
    #    in jenkins output or something - we should use Consul

    encoded_user = 'anB1dHpAsdasdspdC5jb20='  # note these were changed before sharing on github
    encoded_pass = 'enZiN0c0sdadsUm9v'

    decoded_user = base64.b64decode(encoded_user)
    user = str(decoded_user)

    decoded_pass = base64.b64decode(encoded_pass)
    password = str(decoded_pass)

    params = {'username' : user, 'password' : password}
    values = urlencode(params)
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    auth_request = Request('https://api.clientsuccess.com/v1/auth', data=values, headers=headers)

    try:
        auth_response_body = urlopen(auth_request).read()
        auth_response = json.loads(auth_response_body)
        accessToken = auth_response['access_token']
    except Exception as e:
        sys.exit("Failed to obtain an access token. Error thrown was %s" % e)

    if accessToken:
        print("Access Token obtained from Client Success, proceeding.")	# // helpful output for Jenkins
    else:
        sys.exit("Access Token appears invalid. Exiting.")

    return(accessToken)



if __name__ == "__main__":

    # // We take 2 args, type of list to pull and recipient email. Both are required.

    arguments = docopt(__doc__, version='Customer Contact Fetcher v1')

    recipient = arguments['<recipient>']
    if arguments['service']:
        list_type = 'service'
    elif arguments['privacy']:
        list_type = 'privacy'
    else:
        sys.exit("Unknown flag passed to Contacts Fetcher")

    ClientSuccessConnection = clientSuccessAuth()
    call_client_success = ClientSuccessManager(ClientSuccessConnection, list_type, recipient)
    # // If everything went well, we should have our list generated and ready
    print("\nCustomer contact list has been generated and can be found in /home/ubuntu/oa/working/clientsuccess.")

    #sys.exit(0) # // seems like this doesn't help
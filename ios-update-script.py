"""Script to Audit and Upgrade IOS. Requires aaa authentication login and aaa authorisation exec to be configured"""

import sys
from datetime import datetime
from netmiko import ConnectHandler, FileTransfer, ssh_exception
import textfsm
import csv
import ConfigParser
from sqlalchemy import Column, Integer, Unicode, UnicodeText, String, ForeignKey, Boolean
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from Queue import Queue
from threading import Thread, activeCount


engine = create_engine('sqlite:///devices.db')
Base = declarative_base(bind=engine)

class CiscoDevice(Base):

    __tablename__ = 'devices'
    hostname = Column(String)
    ip_address = Column(String, primary_key=True)
    model = Column(String)
    filesystem = Column(String)
    ram = Column(String)
    total_flash = Column(String)
    available_flash = Column(String)
    boot_variable = Column(String)
    current_image = Column(String)
    compliant_image = Column(String)
    compliant = Column(Boolean)
    username = Column(String)
    password = Column(String)
    reload_pending = Column(Boolean)


    def __init__(self, hostname, ip_address=None, model=None, filesystem=None, ram=None, total_flash=0, available_flash=0, boot_variable=None, current_image=None, compliant_image=None, compliant=False, username=None, password=None):
        self.hostname = hostname
        self.ip_address = ip_address
        self.model = model
        self.filesystem = filesystem
        self.RAM = ram
        self.total_flash = total_flash
        self.available_flash = available_flash
        self.boot_variable = boot_variable
        self.current_image = current_image
        self.compliant_image = compliant_image
        self.compliant = compliant
        self.username = username
        self.password = password
        self.reload_pending = False

    def __str__(self):
        return self.hostname


    def audit(self, credentials=None, ios_images=None):

        if credentials != None and ios_images != None:

            auth_success = conn_success = unknown_exception = False
            username = ''
            password = ''

            for credential in credentials:
                try:

                    # TODO: Remove below code to helper method and use threading.

                    username = credential['username']
                    password = credential['password']

                    device = {'device_type': 'cisco_ios',
                              'ip': self.ip_address,
                              'username': username,
                              'password': password}
                    net_connect = ConnectHandler(**device)
                    output = net_connect.send_command('show version')
                    output += net_connect.send_command('show run | inc boot system')
                    output += net_connect.send_command('dir')
                    net_connect.disconnect()

                    auth_success = True
                    conn_success = True

                    break
                except ssh_exception.NetMikoAuthenticationException:
                    auth_success = False
                    conn_success = True
                except ssh_exception.NetMikoTimeoutException:
                    conn_success = False
                    break
                except Exception as e:
                    unknown_exception = True
                    exception_text = e

            if auth_success:

                # Parse the output of the Show Version command
                ver_template = 'show-ver-template.txt'
                fsm_results = parse_output(output, ver_template)
                audit_results = fsm_results[0]

                # Parse the output of the dir flash: command
                dir_template = 'dir-flash-template.txt'
                fsm_results_filelist = parse_output(output, dir_template)


                self.hostname = audit_results[0]
                self.model = audit_results[1]
                self.filesystem = audit_results[8]
                self.ram = audit_results[4]
                self.total_flash = audit_results[6]
                self.available_flash = audit_results[7]
                self.boot_variable = None               # Need to add filter to add this
                self.current_image = audit_results[2]

                if self.model in ios_images.keys():
                    self.compliant_image = ios_images[self.model]
                else:
                    self.compliant_image = None

                if self.current_image == self.compliant_image:
                    self.compliant = True
                else:
                    self.compliant = False

                self.username = username
                self.password = password

                print "Successfully connected to %s (%s) - %s" % (self.hostname, self.ip_address, self.model)

            elif not conn_success:
                print "Connection Timed Out for device %s (%s)" % (self.hostname, self.ip_address)

            elif unknown_exception:
                print "Error connecting to %s - %s" % (self.hostname,unknown_exception)

            else:
                print "Exhausted credentials list for device %s" % self.hostname

        else:
            print "Credentials or IOS Images list empty"

    def clean_unused_files(self):
        # Initiate SSH Connection to device
        device = {'device_type': 'cisco_ios',
                  'ip': self.ip_address,
                  'username': self.username,
                  'password': self.password}
        ssh_conn = ConnectHandler(**device)

        # Loop through the inactive images of the device and attempt to delete.
        for image in self.inactive_images:

            # Perform a dir to determine if the image exists, to avoid an "image not found" command error.
            dir_output = ssh_conn.send_command('dir')

            if image in dir_output and image != self.compliant_image:

                try:
                    # Force delete the inactive image from flash. i.e. 'del /force flash:/image.bin'. Allows for different file systems (flash:, slot0:, etc)
                    ssh_conn.send_command('del /force {}/{}'.format(self.filesystem, image))
                    print "Deleted image file %s from %s" % (image, self.hostname)
                    self.inactive_images.remove(image)

                except Exception as e:
                    print "Error - %s" % e
            else:
                # If file no longer exists (perhaps deleted manually), update the inactive_images list.
                print "Image %s not found or filename matches the compliant image for model %s, skipping...." % (image,self.model)
                self.inactive_images.remove(image)
        ssh_conn.disconnect()

    def update_ios(self):
        # Test if active image is already the compliant image for this model and update the compliance variable
        if self.current_image == self.compliant_image:
            self.compliant = True

        if self.compliant:
            print "Device %s is already compliant, skipping...." % self.hostname

        elif self.username == None:
            print "No saved password for %s, skipping..." % self.hostname

        else:
            print "Device %s is not compliant, begin uploading file" % self.hostname

            # Initiate SSH Connection to device
            device = {'device_type': 'cisco_ios',
                      'ip': self.ip_address,
                      'username': self.username,
                      'password': self.password}
            ssh_conn = ConnectHandler(**device)

            with FileTransfer(ssh_conn, source_file=self.compliant_image, dest_file=self.compliant_image,
                              file_system=self.filesystem) as scp_transfer:

                if not scp_transfer.check_file_exists():
                    if not scp_transfer.verify_space_available():
                        raise ValueError("Insufficient space available on remote device")

                    print "Enabling SCP for device %s" % self.hostname
                    output = ios_scp_handler(ssh_conn, mode='enable')
                    output += ssh_conn.send_config_set(['line vty 0 4','exec-timeout 0 0'])
                    print output

                    print "\nTransferring file to device %s\n" % self.hostname
                    scp_transfer.transfer_file()

                    # print "Disabling SCP"
                    # output = ios_scp_handler(ssh_conn, mode='disable')
                    # print output

                print "\nVerifying file on device %s" % self.hostname
                if scp_transfer.verify_file():
                    print "Source and destination MD5 matches"
                    self.compliant = True
                    self.reload_pending = True
                else:
                    raise ValueError("MD5 failure between source and destination files")


            print "\nSending boot commands & saving configuration"
            # Clear existing Boot Variable
            output = ssh_conn.send_config_set(['no boot system'])
            full_file_name = "{}{}".format(self.filesystem, self.compliant_image)
            boot_cmd = 'boot system {}'.format(full_file_name)
            output += ssh_conn.send_config_set([boot_cmd])
            output += ssh_conn.send_command('wr')
            print output

            ssh_conn.send_command('show run | inc boot system')

            print "Boot variable set for device %s - %s" % (self.hostname, output)

            # If IOS Upload has succeeded, mark the device as compliant to prevent future upgrades prior to device rebooting and the active image being compliant.
            if self.compliant_image in output:
                self.compliance = True
                self.reload_pending = True


    def schedule_reload(self,reload_time):

        # Initiate SSH Connection to device
        device = {'device_type': 'cisco_ios',
                  'ip': self.ip_address,
                  'username': self.username,
                  'password': self.password}
        ssh_conn = ConnectHandler(**device)

        # Send 'reload at' command
        output = ssh_conn.send_command('reload at %s' % reload_time)


def parse_output(raw_text_data, template):
    template = open(template, 'rb')
    re_table = textfsm.TextFSM(template)
    fsm_results = re_table.ParseText(raw_text_data)

    return fsm_results


def ios_scp_handler(ssh_conn, cmd='ip scp server enable', mode='enable'):
    """Enable/disable SCP on Cisco IOS Device."""
    if mode == 'disable':
        cmd = 'no ' + cmd
    return ssh_conn.send_config_set([cmd])


def read_settings_ini():
    config = ConfigParser.ConfigParser(allow_no_value=True)     # Allows the "Hosts" section to just be a list, rather than key value pairs
    config.optionxform = str                                    # Setting option form to string forces case senstivity (necessary for username / password keys)
    config.read('settings.ini')

    # Create a list containing all addresses in the Hosts section
    hosts = config.options('Hosts')

    # Create a dictionary object mapping Device Models to Software Images
    ios_images = {}
    models = config.options('DeviceSoftwareMappings')
    for model in models:
        try:
            ios_images[model] = config.get('DeviceSoftwareMappings', model)
        except Exception as e:
            print e

    # Create a list of dictionary objects containing username / password key / value pairs
    credentials = []
    for credential in config.options('CredentialList'):
        username = credential.split(',')[0]
        password = credential.split(',')[1]
        credentials.append({'username': username, 'password': password})

    # Also return the "config" object, so other functions can write back to the settings.ini file.
    return hosts, ios_images, credentials, config



def enforce_compliance_helper(queue):
    device = queue.get()

    device.update_ios()
    devices_updated.append(device)

    if device.reload_pending:
        devices_requiring_reload.append(device)

    queue.task_done()


def enforce_compliance(devices):

    queue = Queue(maxsize=0)
    max_threads = 10

    global devices_requiring_reload
    global devices_updated
    devices_requiring_reload = []
    devices_updated = []

    for device in devices:
        if not device.compliant:
            queue.put(device)

    while not queue.empty():
        while activeCount() <= max_threads:
            worker = Thread(target=enforce_compliance_helper, args=(queue,))
            worker.setDaemon(True)
            worker.start()

    queue.join()

    print "%s device ios uploaded, %s devices pending reload" % (len(devices_updated), len(devices_requiring_reload))
    for device in devices_requiring_reload:
        print '{} - {}'.format(device.hostname,device.ip_address)


    # schedule_reload = raw_input("\nDo you wish to enter a time now to reload devices? [y, N]")
    #
    # if schedule_reload == 'y':
    #     reload_time = raw_input('\nEnter reload time in format XX XX: ')
    #     # Test reload time is valid value
    #     confirmation = raw_input('\nReload scheduled for %s - confirm? [y,N] ')
    #     if confirmation == 'y':
    #         print "Scheduling reload at %s for %d devices" % (reload_time, len(devices_requiring_reload))
    #         for device in devices_requiring_reload:
    #             device.schedule_reload(reload_time)
    #     else:
    #         print "Skipping reload schedule..."
    #
    # else:
    #     print "Skipping reload scheduling..."



def export_device_to_csv(devices):
    # TODO: Use CSV Writer to write devices to file.
    pass


def device_audit_helper(queue, credentials, ios_images):
    device = queue.get()
    device.audit(credentials, ios_images)
    queue.task_done()


def audit_devices(devices, ios_images, credentials):
    # Connect to devices, gather details, and update device instances

    queue = Queue(maxsize=0)
    max_threads = 30

    for device in devices:
        queue.put(device)

    # Continuous loop while there are still devices in the queue.
    while not queue.empty():
        # Start new threads only if the maximum number of concurrent threads has not been exceeded
        while activeCount() <= max_threads:
            worker = Thread(target=device_audit_helper, args=(queue, credentials, ios_images))
            worker.setDaemon(True)
            worker.start()

    queue.join()



def list_db_devices(s, non_compliant_only=False, reload_pending_only=False):
    print "{:<20} {:<15} {:<15} {:<14} {:<14}".format('[Hostname]','[IP Address]', '[Model]', '[Compliant]', '[Reload Pending]')
    for device in s.query(CiscoDevice):
        if not non_compliant_only and not reload_pending_only:
            print "{:<20} {:<15} {:<15} {:<14} {:<14}".format(device.hostname, device.ip_address, device.model, str(device.compliant), str(device.reload_pending))
        elif reload_pending_only:
            if device.reload_pending:
                print "{:<20} {:<15} {:<15} {:<14} {:<14}".format(device.hostname, device.ip_address, device.model, str(device.compliant), str(device.reload_pending))
        else:
            if not device.compliant:
                print "{:<20} {:<15} {:<15} {:<14} {:<14}".format(device.hostname, device.ip_address, device.model, str(device.compliant), str(device.reload_pending))
    print '\n\n'


def import_devices(hosts, stored_devices, config, s):
    if len(hosts) > 0:

        for host in hosts:
            new_device = CiscoDevice(host, host)
            device_exists = False

            for stored_device in stored_devices:
                if new_device.ip_address == stored_device.ip_address:
                    print "%s (%s) already exists in database" % (stored_device.hostname,stored_device.ip_address)
                    device_exists = True

            if not device_exists:
                s.add(new_device)
                print "%s added to Database" % new_device.hostname

            # Remove host from config file
            config.remove_option('Hosts',host)
    else:
        print "No new hosts to import...\n\n"

    # Update settings.ini file with removed hosts
    with open('settings.ini', 'wb') as configfile:
        config.write(configfile)

    # Commit newly created objects to database
    s.commit()

    return config, s


def get_db_devices(s):
    stored_devices = []
    for device in s.query(CiscoDevice):
        stored_devices.append(device)

    return stored_devices


def main():

    Base.metadata.create_all()
    Session = sessionmaker(bind=engine)
    s = Session()

    # Read settings.ini file to gather list of hosts, model to ios image mappings and credential list
    print "Reading settings.ini file...."
    hosts, ios_images, credentials, config = read_settings_ini()
    print "Read %d hosts, %d device models and %d set(s) of authentication credentials" % (len(hosts), len(ios_images), len(credentials))

    print "Reading Database Contents"
    stored_devices = get_db_devices(s)

    while True:
        print '\n\n###################'
        print 'Main Menu\n\n'
        print '[1] - Load New Devices into Database'
        print '[2] - Display Devices in Database'
        print '[3] - Audit Devices in Database'
        print '[4] - Display Non Compliant Devices'
        print '[5] - Update IOS of Non Compliant Devices'
        print '\n[9] - Exit'
        selection = raw_input('> ')

        if selection == '1':
            # Import Devices into Database
            config, s = import_devices(hosts, stored_devices, config, s)

            # Reread stored devices
            stored_devices = get_db_devices(s)

            # Reread settings.ini
            hosts, ios_images, credentials, config = read_settings_ini()

        elif selection == '2':
            list_db_devices(s)

        elif selection == '3':

            print "\nPerforming Device Audit"
            audit_devices(stored_devices, ios_images, credentials)
            s.commit()

            # Reread stored devices
            stored_devices = get_db_devices(s)

        elif selection == '4':
            non_compliant_only = True
            list_db_devices(s, non_compliant_only)

        elif selection == '5':
            non_compliant_devices = []
            for device in stored_devices:
                if not device.compliant:
                    non_compliant_devices.append(device)
            print "Updating %s Devices" % len(non_compliant_devices)
            enforce_compliance(non_compliant_devices)

            # Commit any changes (i.e. reload_pending, compliance etc) to database.
            s.commit()

            # Reread stored devices
            stored_devices = get_db_devices(s)

        elif selection == '9':
            print "Exiting..."
            break

        else:
            print "Invalid Selection..."





if __name__ == "__main__":
    main()

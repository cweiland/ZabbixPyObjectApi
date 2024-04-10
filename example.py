import logging
import os
import sys

from zabbixpyobjectapi import models, logmanagment
from zabbixpyobjectapi.SingletonZabbixPyObject import SingletonZabbixPyObject

log = logging.getLogger('root')
log.setLevel('INFO')
log.addHandler(logmanagment.LogManagment())
SingletonZabbixPyObject("ENV")

def handle_error(message):
    print("Error:", message)
    print_usage()
    sys.exit(1)

def add_host_to_hostgroup(host, hostgroup):
    hg = models.hostgroup.getFromName(hostgroup)
    if hg is None:
        handle_error("Hostgroup not found")
    hg.addHost(host)

def del_host_from_hostgroup(host, hostgroup):
    hg = models.hostgroup.getFromName(hostgroup)
    if hg is None:
        handle_error("Hostgroup not found")

def link_template_to_host(host, template):
    tpl = models.template.getFromName(template)
    if tpl is None:
        handle_error("Template not found")

def unlink_template_from_host(host, template):
    tpl = models.template.getFromName(template)
    if tpl is None:
        handle_error("Template not found")

def add_main_jmx_interface_to_host(host, ip, dns, port):
    iface = models.HostInterface.addJMXInterface(ip=ip, dns=dns, port=port, host=host)

def del_jmx_interface_to_host(host, ip, dns, port):
    ifaces = models.HostInterface.jmxHostInterfacesFromLotsOfThings(host=host, ip=ip, dns=dns, port=port)
    for interface in ifaces:
        iface = interface.remove()

def print_usage():
    print("Usage:")
    print("python3.9 <script_name> <host_name> <action_argument>")
    print("Available actions:")
    print("- add_host_to_hostgroup.py: <host_name> <hostgroup_name>")
    print("- del_host_from_hostgroup.py: <host_name> <hostgroup_name>")
    print("- link_template_to_host.py: <host_name> <template_name>")
    print("- unlink_template_from_host.py: <host_name> <template_name>")
    print("- add_main_jmx_interface_to_host.py: <host_name> <ip> <dns> <port>")
    print("- del_jmx_interface_to_host.py: <host_name> <ip> <dns> <port>")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        handle_error("Insufficient arguments")

    script_name = os.path.basename(__file__)
    host = sys.argv[1]
    hst = models.host.getFromName(host)
    if hst is None:
        handle_error("Host not found")

    if script_name not in ['add_host_to_hostgroup.py', 'del_host_from_hostgroup.py',
                           'link_template_to_host.py', 'unlink_template_from_host.py',
                           'add_main_jmx_interface_to_host']:
        handle_error("Unknown script name")

    if len(sys.argv) != 4:
        handle_error("Incorrect number of arguments")

    if script_name == 'add_host_to_hostgroup.py':
        add_host_to_hostgroup(hst, sys.argv[2])
    elif script_name == 'del_host_from_hostgroup.py':
        del_host_from_hostgroup(hst, sys.argv[2])
    elif script_name == 'link_template_to_host.py':
        link_template_to_host(hst, sys.argv[2])
    elif script_name == 'unlink_template_from_host.py':
        unlink_template_from_host(hst, sys.argv[2])



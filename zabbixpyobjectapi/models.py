import logging

from zabbixpyobjectapi.Enums import InterfaceType
from zabbixpyobjectapi.SingletonZabbixPyObject import SingletonZabbixPyObject

log = logging.getLogger('root')


class host:
    id: int

    def __init__(self, host_id: int) -> None:
        if host_id is not None:
            self.id = host_id
        else:
            raise ValueError('Host unavailable')

    @staticmethod
    def getFromId(host_id: int):
        hostId = SingletonZabbixPyObject(None).getHostIdFromHostid(hostid=host_id)
        if hostId is None:
            return None
        else:
            return host(host_id=hostId)

    @staticmethod
    def getFromName(name: str):
        hostId = SingletonZabbixPyObject(None).getHostIdFromHostname(hostname=name)
        if hostId is None:
            return None
        else:
            return host(host_id=hostId)

    @property
    def hostName(self):
        return SingletonZabbixPyObject(None).getHostHostFromHostid(hostid=self.id)

    @hostName.setter
    def hostName(self, hosthost: str) -> None:
        SingletonZabbixPyObject(None).setHostHostFromHostid(hostid=self.id, host=hosthost)

    @property
    def visibleName(self):
        return SingletonZabbixPyObject(None).getHostNameFromHostid(hostid=self.id)

    @visibleName.setter
    def visibleName(self, name: str):
        SingletonZabbixPyObject(None).setHostNameFromHostid(hostid=self.id, name=name)

    @property
    def description(self):
        return SingletonZabbixPyObject(None).getHostDescriptionFromHostid(hostid=self.id)

    @description.setter
    def description(self, description: str) -> None:
        SingletonZabbixPyObject(None).setHostDescriptionFromHostid(hostid=self.id, description=description)

    @property
    def templates(self):
        templateids = SingletonZabbixPyObject(None).getTemplateIdsFromHostid(hostid=self.id)
        if templateids is None:
            return []
        return [template(templateid) for templateid in templateids]

    @property
    def groups(self):
        groupids = SingletonZabbixPyObject(None).getGroupsidFromHostid(hostid=self.id)
        if groupids is None:
            return []
        return [hostgroup(groupid) for groupid in groupids]

    @property
    def interfaces(self):
        interfaceids = SingletonZabbixPyObject(None).getHostInterfaceIdsFromHostid(hostid=self.id)
        if interfaceids is None:
            return []
        return [HostInterface(id=interfaceid) for interfaceid in interfaceids]

    @property
    def jmxInterfaces(self) -> list:
        return HostInterface.jmxHostInterfacesFromHosts(host=self)

    @property
    def agentInterfaces(self):
        return HostInterface.agentHostInterfacesFromHosts(host=self)

    def addJMXInterface(self, ip="", dns="", port="", main=None):
        return HostInterface.addJMXInterface(host=self.id, ip=ip, dns=dns, port=port, main=main)

    def addTemplate(self, template) -> bool:
        if SingletonZabbixPyObject(None).linkTemplateToHost(templateid=template.id, hostid=self.id):
            return True
        else:
            return False

    def delTemplate(self, template) -> bool:
        if SingletonZabbixPyObject(None).unlinkTemplateToHost(templateid=template.id, hostid=self.id):
            return True
        else:
            return False


class hostgroup:
    id: int

    def __init__(self, id: int):
        if id is not None:
            self.id = id
        else:
            raise ValueError('Hostgroup unavailable')

    @staticmethod
    def createFromName(name: str):
        hgId = SingletonZabbixPyObject(None).createHostGroup(name=name)
        if hgId is None:
            return None
        else:
            return hostgroup(id=hgId)

    @staticmethod
    def getFromId(id: int):
        hgId = SingletonZabbixPyObject(None).getHostGroupIdFromGroupid(groupid=id)
        if hgId is None:
            return None
        else:
            return hostgroup(id=hgId)

    @staticmethod
    def getFromName(name: str):
        hgId = SingletonZabbixPyObject(None).getHostGroupIdFromGroupname(name=name)
        if hgId is None:
            return None
        else:
            return hostgroup(id=hgId)

    @property
    def name(self):
        return SingletonZabbixPyObject(None).getHostGroupNameFromGroupid(groupid=self.id)

    @name.setter
    def name(self, name: str):
        SingletonZabbixPyObject(None).setHostGroupNameFromGroupid(groupid=self.id, name=name)

    @property
    def hostMembers(self):
        hostids = SingletonZabbixPyObject(None).getHostsidFromGroupid(groupid=self.id)
        if hostids is None:
            return []
        return [host(host_id=hostid) for hostid in hostids]

    def addHost(self, host) -> bool:
        if SingletonZabbixPyObject(None).linkHostToHostgroup(hostid=host.id, groupid=self.id):
            return True
        else:
            return False

    def delHost(self, host) -> bool:
        if SingletonZabbixPyObject(None).unlinkHostToHostgroup(hostid=host.id, groupid=self.id):
            return True
        else:
            return False


class template:
    id: int

    def __init__(self, id: int):
        if id is not None:
            self.id = id
        else:
            raise ValueError('Template unavailable')

    @staticmethod
    def getFromId(id: int):
        tplId = SingletonZabbixPyObject(None).getTemplateidFromTemplateid(templateid=id)
        if tplId is None:
            return None
        else:
            return template(id=tplId)

    @staticmethod
    def getFromName(name: str):
        tplId = SingletonZabbixPyObject(None).getTemplateidFromName(templatename=name)
        if tplId is None:
            return None
        else:
            return template(id=tplId)

    @property
    def name(self):
        return SingletonZabbixPyObject(None).getTemplateNameFromTemplateid(templateid=self.id)

    @name.setter
    def name(self, name):
        SingletonZabbixPyObject(None).setTemplateNameFromTemplateid(templateid=self.id, name=name)

    @property
    def hosts(self):
        hostids = SingletonZabbixPyObject(None).getHostIdsFromTemplateid(templateid=self.id)
        if hostids is None:
            return []
        return [host(host_id=hostid) for hostid in hostids]

    def addHost(self, host) -> bool:
        if SingletonZabbixPyObject(None).linkTemplateToHost(templateid=self.id, hostid=host.id):
            return True
        else:
            return False

    def delHost(self, host) -> bool:
        if SingletonZabbixPyObject(None).unlinkTemplateToHost(templateid=self.id, hostid=host.id):
            return True
        else:
            return False


class HostInterface:
    id: int

    def __init__(self, id: int):
        self.id = id

    @staticmethod
    def jmxHostInterfacesFromHosts(host: host):
        hostinterfacesids = SingletonZabbixPyObject(None).getJMXHostInterfacesIdsFromHostid(hostid=host.id)
        if hostinterfacesids is None:
            return []
        return [HostInterface(id=hostinterfacesid) for hostinterfacesid in hostinterfacesids]

    @staticmethod
    def jmxHostInterfacesFromLotsOfThings(ip: str = None, dns: str = None, port: str = None, host=None):
        hostinterfacesids = SingletonZabbixPyObject(None).getJMXHostInterfacesIdsFromHostid(hostid=host.id, ip=ip,
                                                                                            dns=dns, port=port)
        if hostinterfacesids is None:
            return []
        return [HostInterface(id=hostinterfacesid) for hostinterfacesid in hostinterfacesids]

    @staticmethod
    def agentHostInterfacesFromHosts(host: host):
        hostinterfacesids = SingletonZabbixPyObject(None).getAgentHostInterfacesIdsFromHostid(hostid=host.id)
        if hostinterfacesids is None:
            return []
        return [HostInterface(id=hostinterfacesid) for hostinterfacesid in hostinterfacesids]

    @staticmethod
    def hostInterfaceFromId(interfaceid: int):
        hostinterfacesids = SingletonZabbixPyObject(None).getHostinterfaceIdFromInterfaceId(interfaceid=interfaceid)
        if hostinterfacesids is None:
            return []
        return [HostInterface(id=hostinterfacesid) for hostinterfacesid in hostinterfacesids]

    @staticmethod
    def hostInterfaceFromLotsOfThings(type: InterfaceType = None, ip: str = None, dns: str = None, port=None,
                                      useip: bool = None, main: bool = None, host=None) -> list:
        if host is None:
            host_id = None
        else:
            host_id = host.id
        hostinterfacesids = SingletonZabbixPyObject(None).getHostinterfacesIdsFromLotsOfThings(type=type, ip=ip,
                                                                                               dns=dns,
                                                                                               useip=useip,
                                                                                               main=main, port=port,
                                                                                               hostid=host_id)
        if hostinterfacesids is None:
            return []
        return [HostInterface(id=hostinterfacesid) for hostinterfacesid in hostinterfacesids]

    @staticmethod
    def isExists(type: InterfaceType = None, ip: str = None, dns: str = None, port: int = None, useip: bool = None,
                 main: bool = None, host=None) -> bool:
        return SingletonZabbixPyObject(None).interfacesExists(type=type, ip=ip, dns=dns, useip=useip, main=main,
                                                              port=port,
                                                              hostid=host.id)

    @property
    def type(self) -> InterfaceType:
        return SingletonZabbixPyObject(None).getHostinterfaceTypeFromInterfaceId(interfaceid=self.id)

    @property
    def ip(self) -> str:
        return SingletonZabbixPyObject(None).getHostinterfaceIpFromInterfaceId(interfaceid=self.id)

    @property
    def dns(self) -> str:
        return SingletonZabbixPyObject(None).getHostinterfaceDnsFromInterfaceId(interfaceid=self.id)

    @property
    def useip(self) -> bool:
        return SingletonZabbixPyObject(None).getHostinterfaceUseipFromInterfaceId(interfaceid=self.id)

    @property
    def main(self) -> bool:
        return SingletonZabbixPyObject(None).getHostinterfaceUseipFromInterfaceId(interfaceid=self.id)

    @property
    def port(self) -> int:
        return SingletonZabbixPyObject(None).getHostinterfacePortFromInterfaceId(interfaceid=self.id)

    @property
    def host(self) -> int:
        return SingletonZabbixPyObject(None).getHostinterfaceHostFromInterfaceId(interfaceid=self.id)

    @staticmethod
    def create(type: InterfaceType = None, ip: str = None, dns: str = None, port: int = None, main: bool = None,
               host=None):
        if host is None:
            log.error("Host is not setted")
            return None
        return SingletonZabbixPyObject(None).addInterface(type=type.value, ip=ip, dns=dns, main=main, port=port,
                                                          hostid=host.id)

    def remove(self):
        return SingletonZabbixPyObject(None).delInterface(interfaceid=self.id)

    @staticmethod
    def addJMXInterface(ip=None, dns=None, port=None, main=None, host=None):
        HostInterface.create(type=InterfaceType.JMX, ip=ip, dns=dns, port=port, main=main, host=host)

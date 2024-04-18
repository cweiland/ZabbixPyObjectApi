import logging
import os
from zabbixpyobjectapi.SingletonMeta import SingletonMeta
from pyzabbix import ZabbixAPIException, ZabbixAPI
from zabbixpyobjectapi.settings import settings, EmptySection

log = logging.getLogger('root')


class SingletonZabbixPyObject(metaclass=SingletonMeta):
    _user: str
    _password: str
    _url: str
    _sslcheck: bool
    _server: str
    zapi: ZabbixAPI = None

    #region Api
    def __init__(self, environment):
        try:
            settings_section = settings.system.getsection(environment)
            if settings_section == EmptySection():
                log.error("Environment {} is unknown.".format(environment))
                raise ValueError("Environment {} is unknown.".format(environment))
            log.debug("Get configuration data {}".format(environment))
            _proxy = settings_section.get('proxy')
            if _proxy is None:
                _proxy = "N/A"
            else:
                os.environ["HTTP_PROXY"] = _proxy
                os.environ["HTTPS_PROXY"] = _proxy
            log.debug("HTTP/S proxy : {}".format(_proxy))
            self._user = settings_section.get('user')
            log.debug("Username : {}".format(self._user))
            self._password = settings_section.get('password')
            log.debug("Password : {}".format(self._password))
            self._token = settings_section.get('token')
            log.debug("token : {}".format(self._token))
            self._server = settings_section.get('server')
            log.debug("Server : {}".format(self._server))
            if self._token is None or self._server is None:
                if self._user is None or self._password is None or self._server is None:
                    log.error("Credentials or server missing !")
                    raise ValueError(f'Credentials or server missing !')
            _port = settings_section.get('port') or "443"
            log.debug("Port: {}".format(_port))
            _protocol = settings_section.get('protocol') or "https"
            log.debug("Protocol : {}".format(_protocol))
            _path = settings_section.get('path') or "/zabbix/"
            log.debug("Path : {}".format(_path))
            self._url = _protocol + "://" + self._server + ":" + _port + _path
            log.info("URL : {}".format(self._url))
            self._sslcheck = settings_section.get('sslcheck') or 'True'
            if self._sslcheck == 'False':
                self._sslcheck = False
                from urllib3.exceptions import InsecureRequestWarning
                from urllib3 import disable_warnings
                disable_warnings(InsecureRequestWarning)
            else:
                self._sslcheck = True
            log.debug("SSL Check : {}".format(self._sslcheck))
        except FileNotFoundError as ex:
            log.error("Config file not found : {}".format(ex.filename))
            raise ValueError("Config file not found : {}".format(ex.filename))
        except Exception as ex:
            log.error("Unknown exception loading settings")
            print(ex)
            raise ValueError("Unknown exception loading settings")

    def connect(self) -> bool:
        try:
            log.info("Connection to {}".format(self._server))
            self.zapi = ZabbixAPI(server=self._url)
            self.zapi.session.verify = self._sslcheck
            if self._token is None:
                log.info("Login with {}".format(self._user))
                self.zapi.login(self._user, self._password)
            else:
                log.info("Login with token")
                self.zapi.login(api_token=self._token)
            if self.zapi.check_authentication():
                version = self.zapi.api_version()
                log.info("Connected to {} ({})".format(self._server, version))
                return True
            else:
                log.error("Not connected")
                raise ValueError("Not connected")
        except ZabbixAPIException as ex:
            log.error("Connection error")
            log.error(ex)
            raise ValueError("Connection error")

    def endpoint(self):
        if self.zapi is None:
            self.connect()
        if self.zapi.check_authentication():
            return self.zapi
        else:
            log.warning("Not connected")
            self.connect()
            return self.endpoint()

    #endregion-

    # region Host
    # region Common functions
    def apiHostGet(self, filter: dict, output: str, mustBeOne: bool = True):
        log.debug("apiHostGet(filter={}, output={})".format(filter, output))
        api = self.endpoint()
        try:
            hosts = api.host.get(
                filter=filter,
                output=output,
                selectGroups=["groupid"],
                selectParentTemplates=["templateid"],
                selectInterfaces=["interfaceid"]
            )
        except Exception as error:
            log.error("Zabbix API issue on host.get:", error)
            return None
        if not hosts:
            log.warning("No host found")
            return None
        if mustBeOne:
            if len(hosts) > 1:
                log.warning("Too many hosts")
                return None
            result = hosts[0][output]
        else:
            result = [host[output] for host in hosts]
        log.info("Hosts found")
        return result

    def apiHostUpdate(self, hostid: str, fields: dict):
        log.debug("apiHostUpdate(hostid={}, fields={})".format(hostid, fields))
        api = self.endpoint()
        if not self.isHostIdExists(hostid=hostid):
            return False
        try:
            api.host.update(
                hostid=hostid,
                **fields
            )
        except Exception as error:
            log.error("Zabbix API issue with host.update:", error)
            return False
        else:
            log.info("Host updated")
            return True

    #endregion
    #region Getters
    def getHostIdFromHostid(self, hostid):
        log.debug("getHostIdFromHostid({})".format(hostid))
        return self.apiHostGet(filter={"hostid": hostid}, output="hostid")

    def getHostIdFromHostname(self, hostname):
        log.debug("getHostIdFromHostname({})".format(hostname))
        return self.apiHostGet(filter={"name": hostname}, output="hostid")

    def getHostNameFromHostid(self, hostid):
        log.debug("getHostNameFromHostid({})".format(hostid))
        return self.apiHostGet(filter={"hostid": hostid}, output="name")

    def getHostHostFromHostid(self, hostid):
        log.debug("getHostHostFromHostid({})".format(hostid))
        return self.apiHostGet(filter={"hostid": hostid}, output="host")

    def getHostDescriptionFromHostid(self, hostid):
        log.debug("getHostDescriptionFromHostid({})".format(hostid))
        return self.apiHostGet(filter={"hostid": hostid}, output="description")

    #endregion
    #region Setters
    def setHostNameFromHostid(self, hostid, name):
        log.debug("setHostNameFromHostid({},{})".format(hostid, name))
        fields = {"name": name}
        if self.apiHostUpdate(hostid=hostid, fields=fields):
            log.info("Hostname {}:{} updated".format(hostid, name))
            return True
        else:
            log.warning("Hostname {} not updated".format(hostid))
            return False

    def setHostHostFromHostid(self, hostid, host):
        log.debug("setHostHostFromHostid({},{})".format(hostid, host))
        fields = {"host": host}
        if self.apiHostUpdate(hostid=hostid, fields=fields):
            log.info("Host {}:{} updated".format(hostid, host))
            return True
        else:
            log.warning("Host {} not updated".format(hostid))
            return False

    def setHostDescriptionFromHostid(self, hostid, description):
        log.debug("setHostDescriptionFromHostid({},{})".format(hostid, description))
        fields = {"description": description}
        if self.apiHostUpdate(hostid=hostid, fields=fields):
            log.info("Host {}:{} updated".format(hostid, description))
            return True
        else:
            log.warning("Host {} not updated".format(hostid))
            return False

    #endregion
    #region Test
    def isHostExists(self, hostname):
        log.debug("isHostExists({})".format(hostname))
        data = self.getHostIdFromHostname(hostname=hostname)
        if data is not None:
            log.info("host exists")
            return True
        else:
            log.info("host not exists")
            return False

    def isHostIdExists(self, hostid):
        log.debug("isHostIdExists({})".format(hostid))
        data = self.getHostIdFromHostid(hostid=hostid)
        log.debug("isHostIdExists({})".format(hostid))
        if data is not None:
            log.info("host exists")
            return True
        else:
            log.info("host not exists")
            return False

    #endregion

    # endregion

    #region Hostgroup
    #region Common functions
    def apiHostgroupCreate(self, name):
        log.debug("apiHostgroupCreate()".format(name))
        api = self.endpoint()
        try:
            hostgroup = api.hostgroup.create(name=name)
        except Exception as error:
            log.error("Zabbix API issue on hostgroup.create:", error)
            return None
        else:
            result = hostgroup["groupids"][0]
            log.info("Host group created")
            return result

    def apiHostgroupGet(self, filter: dict, output: str, mustBeOne: bool = True):
        log.debug("apiHostgroupGet({},{})".format(filter, output))
        api = self.endpoint()
        try:
            hostgroups = api.hostgroup.get(
                filter=filter,
                output="extend",
                selectHosts=["hostid"]
            )
        except Exception as error:
            log.error("Zabbix API issue on hostgroup.get:", error)
            return None
        if not hostgroups:
            log.warning("No hostgroup found")
            return None
        if mustBeOne:
            if len(hostgroups) > 1:
                log.warning("Too many hostgroup")
                return None
            result = hostgroups[0][output]
        else:
            result = [hostgroup[output] for hostgroup in hostgroups]
        log.info("hostgroups found")
        return result

    def apiHostgroupUpdate(self, groupid: str, fields: dict):
        log.debug("apihostgroupUpdate({},{})".format(groupid, fields))
        api = self.endpoint()
        try:
            api.hostgroup.update(
                groupid=groupid,
                **fields
            )
        except Exception as error:
            log.error("Zabbix API issue with hostgroup.update:", error)
            return False
        else:
            log.info("Hostgroup updated")
            return True

    # endregion
    #region Create
    def createHostGroup(self, name):
        log.debug("createHostGroup({})".format(name))
        if not self.isHostGroupExists(name):
            return self.apiHostgroupCreate(name)
        else:
            log.info("Host group already exists")
            return None

    #endregion
    #region Getters
    def getHostGroupIdFromGroupname(self, name):
        log.debug("getHostGroupIdFromGroupname({})".format(name))
        return self.apiHostgroupGet(filter={"name": name}, output="groupid")

    def getHostGroupIdFromGroupid(self, groupid):
        log.debug("getHostGroupIdFromGroupid({})".format(groupid))
        return self.apiHostgroupGet(filter={"groupid": groupid}, output="groupid")

    def getHostGroupNameFromGroupid(self, groupid):
        log.debug("getHostGroupNameFromGroupid{}".format(groupid))
        return self.apiHostgroupGet(filter={"groupid": groupid}, output="name")

    #endregion
    #region Setters
    def setHostGroupNameFromGroupid(self, groupid, name):
        log.debug("setHostGroupNameFromGroupid({},{})".format(groupid, name))
        fields = {"name": name}
        if self.apiHostgroupUpdate(groupid=groupid, fields=fields):
            log.info("Hostgroup {}:{} updated".format(groupid, name))
            return True
        else:
            log.info("Hostgroup {} not updated".format(groupid))
            return False

    #endregion
    #region Test
    def isHostGroupExists(self, hostgroup):
        log.debug("isHostGroupExists({})".format(hostgroup))
        data = self.getHostGroupIdFromGroupname(name=hostgroup)
        if data is not None:
            log.info("Hostgroup {} exists".format(hostgroup))
            return True
        else:
            log.warning("Hostgroup {} not exists".format(hostgroup))
            return False

    def isHostGroupIdExists(self, groupid):
        log.debug("isHostGroupIdExists({})".format(groupid))
        data = self.getHostGroupIdFromGroupid(groupid=groupid)
        if data is not None:
            log.info("Hostgroup {} exists".format(groupid))
            return True
        else:
            log.warning("Hostgroup {} not exists".format(groupid))
            return False

    #endregion
    #endregion

    #region Interface
    #region Common functions
    def apiInterfacesGet(self, filter: dict, output: str, mustBeOne: bool = True):
        log.debug("apiInterfacesGet({},{})".format(filter, output))
        api = self.endpoint()
        try:
            hostinterfaces = api.hostinterface.get(
                filter=filter,
                output=output,
            )
        except Exception as error:
            log.error("Zabbix API issue on hostinterface.get:", error)
            return None
        if not hostinterfaces:
            log.warning("No hostinterface found")
            return None
        if mustBeOne:
            if len(hostinterfaces) > 1:
                log.warning("Too many interfaces")
                return None
            result = hostinterfaces[0][output]
        else:
            result = [hostinterface[output] for hostinterface in hostinterfaces]
        log.info("hostinterfaces found")
        return result

    #endregion
    #region Getters
    def getHostinterfacesIdsFromLotsOfThings(self, interfaceid=None, type=None, ip=None, dns=None, useip=None,
                                             main=None, hostid=None, port=None):
        log.debug("getHostinterfacesIdFromLotsOfThings({},{},{},{},{},{},{})".format(type, ip, dns, useip, main, hostid,
                                                                                     port))
        filterQuery = {}
        if type is not None:
            filterQuery["type"] = type
        if ip is not None:
            filterQuery["ip"] = ip
        if dns is not None:
            filterQuery["dns"] = dns
        if useip is not None:
            filterQuery["useip"] = useip
        if main is not None:
            filterQuery["main"] = main
        if hostid is not None:
            filterQuery["hostid"] = hostid
        if port is not None:
            filterQuery["port"] = port
        if interfaceid is not None:
            filterQuery["interfaceid"] = interfaceid
        interfacedata = self.apiInterfacesGet(filter=filterQuery, output="interfaceid", mustBeOne=False)
        return interfacedata

    def getJMXHostInterfacesIdsFromHostid(self, hostid, ip=None, dns=None, useip=None, main=None, port=None):
        log.debug("getJMXHostInterfacesFromHostid({},{},{},{},{},{})".format(ip, dns, useip, main, hostid, port))
        return self.getHostinterfacesIdsFromLotsOfThings(type=4, hostid=hostid, ip=ip, dns=dns, useip=useip, port=port,
                                                         main=main)

    def getAgentHostInterfacesIdsFromHostid(self, hostid, ip=None, dns=None, useip=None, main=None, port=None):
        log.debug("getAgentHostInterfacesFromHostid({},{},{},{},{},{})".format(ip, dns, useip, main, hostid, port))
        return self.getHostinterfacesIdsFromLotsOfThings(type=1, hostid=hostid, ip=ip, dns=dns, useip=useip, port=port,
                                                         main=main)

    def getSNMPHostInterfacesIdsFromHostid(self, hostid, ip=None, dns=None, useip=None, main=None, port=None):
        log.debug("getSNMPHostInterfacesFromHostid({},{},{},{},{},{})".format(ip, dns, useip, main, hostid, port))
        return self.getHostinterfacesIdsFromLotsOfThings(type=2, hostid=hostid, ip=ip, dns=dns, useip=useip, port=port,
                                                         main=main)

    def getIPMIHostInterfacesIdsFromHostid(self, hostid, ip=None, dns=None, useip=None, main=None, port=None):
        log.debug("getIPMIHostInterfacesFromHostid({},{},{},{},{},{})".format(ip, dns, useip, main, hostid, port))
        return self.getHostinterfacesIdsFromLotsOfThings(type=3, hostid=hostid, ip=ip, dns=dns, useip=useip, port=port,
                                                         main=main)

    def getHostinterfaceIdFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceIdFromInterfaceId({})".format(interfaceid))
        output = "interfaceid"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfaceTypeFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceIdFromInterfaceId({})".format(interfaceid))
        output = "type"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfaceIpFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceIpFromInterfaceId({})".format(interfaceid))
        output = "ip"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfaceDnsFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceDnsFromInterfaceId({})".format(interfaceid))
        output = "dns"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfacePortFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfacePortFromInterfaceId({})".format(interfaceid))
        output = "port"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfaceUseipFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceUseipFromInterfaceId({})".format(interfaceid))
        output = "useip"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfaceMainFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceMainFromInterfaceId({})".format(interfaceid))
        output = "main"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfaceDetailsFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceDetailsFromInterfaceId({})".format(interfaceid))
        output = "details"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    def getHostinterfaceHostFromInterfaceId(self, interfaceid):
        log.debug("getHostinterfaceHostFromInterfaceId({})".format(interfaceid))
        output = "hostid"
        filter = {"interfaceid": interfaceid}
        return self.apiInterfacesGet(filter=filter, output=output, mustBeOne=True)

    #endregion
    #region Tests
    def interfacesExists(self, type, ip, dns, port, useip, main, hostid):
        log.debug("InterfaceExists({}, {}, {}, {}, {}, {})".format(type, ip, dns, port, useip, main, hostid))
        data = self.getHostinterfacesIdsFromLotsOfThings(type=type, ip=ip, dns=dns, useip=useip, main=main,
                                                         hostid=hostid, port=port)
        if data is not None:
            log.info("InterfacesExists")
            return True
        else:
            log.warning("Interface not found")
            return False

    def interfaceIdExists(self, id):
        log.debug("interfaceIdExists({})".format(id))
        data = self.getHostinterfacesIdsFromLotsOfThings(interfaceid=id)
        if data is not None:
            log.info("InterfacesExists")
            return True
        else:
            log.warning("Interface not found")
            return False

    #endregion
    #endregion

    #region Template
    #region Common functions
    def apiTemplatesGet(self, filter: dict, output: str, mustBeOne: bool = True):
        log.debug("apiTemplatesGet(filter={}, output={})".format(filter, output))
        api = self.endpoint()
        try:
            templates = api.template.get(
                filter=filter,
                output=output,
            )
        except Exception as error:
            log.error("Zabbix API issue on template.get:", error)
            return None
        if not templates:
            log.warning("No template found")
            return None
        if mustBeOne:
            if len(templates) > 1:
                log.warning("Too many templates")
                return None
            result = templates[0][output]
        else:
            result = [template[output] for template in templates]
        log.info("Template found")
        return result

    def apiTemplatesUpdate(self, templateid: str, fields: dict):
        log.debug("apiTemplatesUpdate(templateid={}, fields={})".format(templateid, fields))
        api = self.endpoint()
        if not self.isTemplateIdExists(templateid=templateid):
            return False
        try:
            api.template.update(
                templateid=templateid,
                **fields
            )
        except Exception as error:
            log.error("Zabbix API issue with template.update:", error)
            return False
        else:
            log.info("Template updated")
            return True

    #endregion
    #region Getters
    def getTemplateidFromName(self, templatename):
        log.debug("getTemplateidFromName({})".format(templatename))
        filter = {"name": templatename}
        output = "templateid"
        return self.apiTemplatesGet(filter=filter, output=output)

    def getTemplateidFromTemplateid(self, templateid):
        log.debug("getTemplateidFromTemplateid({})".format(templateid))
        filter = {"hostid": templateid}
        output = "templateid"
        return self.apiTemplatesGet(filter=filter, output=output)

    def getTemplateNameFromTemplateid(self, templateid):
        log.debug("getTemplateNameFromTemplateid({})".format(templateid))
        filter = {"hostid": templateid}
        output = "name"
        return self.apiTemplatesGet(filter=filter, output=output)

    #endregion
    #region Setters
    def setTemplateNameFromTemplateid(self, templateid, name):
        log.debug("setTemplateNameFromTemplateid({},{})".format(templateid, name))
        fields = {"name": name}
        if self.apiTemplatesUpdate(fields=fields, templateid=templateid):
            log.info("Template {}:{} updated".format(templateid, name))
            return True
        else:
            log.warning("Template {} not updated".format(templateid))
            return False

    #endregion
    #region Tests
    def isTemplateIdExists(self, templateid):
        log.debug("isTemplateIdExists({})".format(templateid))
        data = self.getTemplateidFromTemplateid(templateid=templateid)
        if data is not None:
            log.info("Template exists")
            return True
        else:
            log.warning("Template does not exist")
            return False

    def isTemplateExists(self, templatename):
        log.debug("isTemplateExists({})".format(templatename))
        data = self.getTemplateidFromName(templatename=templatename)
        if data is not None:
            log.info("Template exists")
            return True
        else:
            log.warning("Template does not exist")
            return False

    #endregion
    #endregion

    #region Host-HostGroup
    #region Getters
    def getHostsidFromGroupid(self, groupid):
        log.debug("getHostsFromGroupid({})".format(groupid))
        results = self.apiHostgroupGet(filter={"groupid": groupid}, output="hosts")
        if results is not None:
            return [result["hostid"] for result in results]
        else:
            return None

    def getGroupsidFromHostid(self, hostid):
        log.debug("getGroupsidFromHostid({})".format(hostid))
        results = self.apiHostGet(filter={"hostid": hostid}, output="groups")
        if results is not None:
            return [result["groupid"] for result in results]
        else:
            return None

    #endregion
    #region Setters
    def linkHostToHostgroup(self, hostid, groupid):
        log.debug("linkHostToHostgroup")
        api = self.endpoint()
        if self.isHostIdExists(hostid=hostid) and self.isHostGroupIdExists(groupid=groupid):
            log.info("Host {} and group {} exists".format(hostid, groupid))
            if self.isHostLinkedToHostgroup(hostid=hostid, groupid=groupid):
                return False
            try:
                api.hostgroup.massadd(
                    groups={"groupid": groupid},
                    hosts={"hostid": hostid}
                )
            except Exception as error:
                log.error("Zabbix API issue with hostgroup.massadd:", error)
                return False
            else:
                log.info("Host {} linked to hostgroup {}".format(hostid, groupid))
                return True
        else:
            log.warning("Host {} and group {} not exists".format(hostid, groupid))
            return False

    def unlinkHostToHostgroup(self, hostid: int, groupid: int):
        log.debug("unlinkHostToHostgroup")
        api = self.endpoint()
        if self.isHostIdExists(hostid=hostid) and self.isHostGroupIdExists(groupid=groupid):
            if not self.isHostLinkedToHostgroup(hostid=hostid, groupid=groupid):
                return False
            try:
                api.hostgroup.massremove(
                    groupids=groupid,
                    hostids=hostid
                )
            except Exception as error:
                log.error("Zabbix API issue with hostgroup.massremove:", error)
                return False
            else:
                log.info("Host {} unlinked to hostgroup {}".format(hostid, groupid))
                return True
        else:
            log.warning("Host {} and group {} not exists".format(hostid, groupid))
            return False

    #endregion
    #region Test
    def isHostLinkedToHostgroup(self, hostid, groupid):
        log.debug("isHostLinkedToHostgroup({},{})".format(hostid, groupid))
        groupids = self.getGroupsidFromHostid(hostid)
        if groupids is not None and any(element == groupid for element in groupids):
            log.info("Host {} and group {} are linked")
            return True
        else:
            log.warning("Host {} and group {} are not linked")
            return False

    #endregion
    #endregion

    #region Template-Host
    #region Getters
    def getTemplateIdsFromHostid(self, hostid):
        log.debug("getHostTemplatesFromHostid({})".format(hostid))
        results = self.apiHostGet(filter={"hostid": hostid}, output="parentTemplates")
        if results is not None:
            return [result["templateid"] for result in results]
        else:
            return None

    def getHostIdsFromTemplateid(self, templateid):
        log.debug("getHostsFromTemplateid({})".format(templateid))
        results = self.apiTemplatesGet(filter={"templateid": templateid}, output="Hosts")
        if results is not None:
            return [result["hostid"] for result in results]
        else:
            return None

    #endregion
    #region Setters
    def linkTemplateToHost(self, templateid, hostid):
        log.debug("linkTemplateToHost({},{})".format(templateid, hostid))
        api = self.endpoint()
        if self.isTemplateIdExists(templateid=templateid) and self.isHostIdExists(hostid=hostid):
            log.info("Template {} and host {} exists".format(templateid, hostid))
            if self.isHostLinkedToTemplate(hostid=hostid, templateid=templateid):
                return False
            try:
                api.host.massadd(
                    templates={"templateid": templateid},
                    hosts={"hostid": hostid}
                )
            except Exception as error:
                log.error("Zabbix API issue with host.massadd:", error)
                return False
            else:
                log.info("Template {} linked to host {}".format(templateid, hostid))
                return True
        else:
            log.warning("Template {} and host {} not exists".format(templateid, hostid))
            return False

    def unlinkTemplateToHost(self, templateid, hostid):
        log.debug("unlinkTemplateToHost({},{})".format(templateid, hostid))
        api = self.endpoint()
        if self.isTemplateIdExists(templateid=templateid) and self.isHostIdExists(hostid=hostid):
            log.info("Template {} and host {} exists".format(templateid, hostid))
            if not self.isHostLinkedToTemplate(hostid=hostid, templateid=templateid):
                return False
            try:
                api.host.massremove(
                    templateids_clear=templateid,
                    hostids=hostid
                )
            except Exception as error:
                log.error("Zabbix API issue with host.massremove:", error)
                return False
            else:
                log.info("Template {} unlinked to host {}".format(templateid, hostid))
                return True
        else:
            log.warning("Template {} and host {} not exists".format(templateid, hostid))
            return False

    #endregion
    #region Test
    def isHostLinkedToTemplate(self, hostid, templateid):
        log.debug("isHostLinkedToTemplate({},{})".format(hostid, templateid))
        templateids = self.getTemplateIdsFromHostid(hostid=hostid)
        if templateids is not None and any(element == templateid for element in templateids):
            log.info("Host {} and template {} are linked".format(hostid, templateid))
            return True
        else:
            log.warning("Host {} and template {} are not linked".format(hostid, templateid))
            return False

    #endregion
    #endregion

    #region Host-Interface
    #region Getters
    def getHostInterfaceIdsFromHostid(self, hostid):
        log.debug("getHostInterfacesByHostid({})".format(hostid))
        results = self.apiHostGet(filter={"hostid": hostid}, output="interfaces")
        if results is not None:
            return [result["interfaceid"] for result in results]
        else:
            return None

    def getHostIdFromHostInterfaceId(self, interfaceid):
        log.debug("getHostIdByHostInterfaceId({})".format(interfaceid))
        result = self.apiInterfacesGet(filter={"interfaceid": interfaceid}, output="hostid", mustBeOne=True)
        return result

    #endregion
    #region Setters
    def addInterface(self, type=None, ip=None, dns=None, port=None, main='0', hostid=None):
        log.debug("addInterface({},{},{},{},{},{})".format(type, ip, dns, port, main, hostid))
        if type is None or type < 1 or type > 4:
            log.error("Type is required and must be 1, 2, 3 or 4")
            return None
        if ip is None and dns is None:
            log.error("DNS or IP is required")
            return None
        if port is None:
            log.error("Port required")
            return None
        if hostid is None:
            log.error("HostId required")
            return None
        if main is None:
            log.error("Main is required")
            return None
        useip = 0
        if not ip is None:
            useip = 1
        api = self.endpoint()
        if self.isHostIdExists(hostid) and not self.interfacesExists(type=type, ip=ip, dns=dns, port=port, useip=useip,
                                                                     main=main, hostid=hostid):
            log.info("Hostinterface not exists and Host {} exists".format(hostid))
            try:
                result = api.hostinterface.create(
                    hostid=hostid,
                    main=main,
                    type=type,
                    useip=useip,
                    ip=ip,
                    dns=dns,
                    port=port
                )
            except Exception as error:
                log.error("Zabbix API issue with hostinterface.create:", error)
                return None
            else:
                log.info("Interface added")
                return result
        else:
            log.info("Hostinterface and Host {} exists".format(hostid))
            return None

    def addJMXInterface(self, ip=None, dns=None, port=None, hostid=None, main=None):
        log.debug("addJMXInterface")

        if self.addInterface(type=4, ip=ip, dns=dns, port=port, hostid=hostid, main=main):
            log.info("JMX Interface added")
            return True
        else:
            log.error("JMX Interface not added")
            return False

    def delInterface(self, interfaceid):
        log.debug("delInterface({})".format(interfaceid))
        api = self.endpoint()
        if not self.interfaceIdExists(id=interfaceid):
            log.info("Hostinterface {} exists".format(interfaceid))
            try:
                api.hostinterface.delete(
                    [id]
                )
            except Exception as error:
                log.error("Zabbix API issue with hostinterface.delete:", error)
                return False
            else:
                log.info("Interface deleted")
                return True
        else:
            log.info("Hostinterface not {} exists".format(interfaceid))
            return False

    #endregion
    #endregion

    #region Tools
    @staticmethod
    def intersection(lst1, lst2):
        lst3 = [value for value in lst1 if value in lst2]
        return lst3
    #endregion

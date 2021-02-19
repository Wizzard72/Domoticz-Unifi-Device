# Unifi-Presence plugin
#
# Author: Wizzard72
#
"""
<plugin key="UnifiPresence" name="Unifi Device" author="Wizzard72" version="0.1" wikilink="https://github.com/Wizzard72/Domoticz-Unifi-Device">
    <description>
        <h2>Unifi Device Detection plugin</h2><br/>
        This plugin reads if the devices are on the Unifi network.
        
    </description>
    <params>
        <param field="Address" label="IP Address / DNS name of the Unifi Controller" width="200px" required="true" default="127.0.0.1"/>
        <param field="Port" label="Port" width="30px" required="true" default="8443"/>
        <param field="Username" label="Username" width="200px" required="true" default="admin@unifi.com"/>
        <param field="Password" label="Password" width="600px" required="true" default="password" password="true"/>
        <param field="Mode1" label="Site Name" width="200px" required="true" default="default"/>
        <param field="Mode2" label="MAC Device Addresses" width="600px" required="true" default="Phone1=1A:2B:3C:4D:5E:6F,Phone2=7A:8B:9C:AD:BE:CF"/>
        <param field="Mode4" label="Select Unifi Controller" width="150px">
            <options>
                <option label="Unifi Controller" value="unificontroller" default="true" />
                <option label="Dream Machine Pro" value="dreammachinepro"/>
            </options>
        </param>
        <param field="Mode5" label="Posibility to block devices from the network?" width="75px">
            <options>
                <option label="Yes" value="Yes"/>
                <option label="No" value="No"  default="true" />
            </options>
        </param>
        <param field="Mode6" label="Debug" width="75px">
            <options>
                <option label="None" value="0"  default="true" />
                <option label="Python Only" value="2"/>
                <option label="Basic Debugging" value="62"/>
                <option label="Basic+Messages" value="126"/>
                <option label="Connections Only" value="16"/>
                <option label="Connections+Queue" value="144"/>
                <option label="All" value="-1"/>
            </options>
        </param>
    </params>
</plugin>
"""
import Domoticz
import socket
import json
import re
import requests
import urllib
import time
from requests import Session
from typing import Pattern, Dict, Union
from datetime import datetime
# https://ubntwiki.com/products/software/unifi-controller/api


class BasePlugin:
    _unifiConn = False
    override_time = 0
    hostAuth = False
    _Cookies = None
    _csrftoken = None
    cookie = None
    cookieAvailable = False
    phone_name = ""
    Matrix = ""
    count_g_device = 0
    _devices_found = {}
    _login_data = {}
    _current_status_code = None
    versionCheck = None
    _block_data = {}
    _block_data['cmd'] = None
    _block_data['mac'] = None
    _login_data['username'] = None
    _login_data['password'] = None
    _site = None
    _verify_ssl = False
    _baseurl = None
    _session = Session()
    _lastloginfailed = False
    
    def __init__(self):
        return

    def onStart(self):
        strName = "onStart: "
        Domoticz.Debug(strName+"called")

        self._login_data['username'] = Parameters["Username"]
        self._login_data['password'] = Parameters["Password"]
        self._login_data['remember'] = True
        self._site = Parameters["Mode1"]
        self._verify_ssl = False
        self._baseurl = 'https://'+Parameters["Address"]+':'+Parameters["Port"]
        self._session = Session()

        if (Parameters["Mode6"] != "0"):
            Domoticz.Debugging(int(Parameters["Mode6"]))
        else:
            Domoticz.Debugging(0)

        # check if version of domoticz is 2020.2 or higher
        try:
            if int(Parameters["DomoticzVersion"].split('.')[0]) < 2020:  # check domoticz major version
                Domoticz.Error(
                    "Domoticz version required by this plugin is 2020.2 (you are running version {}).".format(
                        Parameters["DomoticzVersion"]))
                Domoticz.Error("Plugin is therefore disabled")
                self.setVersionCheck(False, "onStart")
            else:
                self.setVersionCheck(True, "onStart")
        except Exception as err:
            Domoticz.Error("Domoticz version check returned an error: {}. Plugin is therefore disabled".format(err))
            self.setVersionCheck(False, "onStart")
        if not self.versionCheck:
            return

        # load custom images
        if "UnifiPresenceAnyone" not in Images:
            Domoticz.Log(strName+"Add UnifiPresenceAnyone icons to Domoticz")
            Domoticz.Image("uanyone.zip").Create()

        if "UnifiPresenceOverride" not in Images:
            Domoticz.Log(strName+"Add UnifiPresenceOverride icons to Domoticz")
            Domoticz.Image("uoverride.zip").Create()

        if "UnifiPresenceDevice" not in Images:
            Domoticz.Log(strName+"Add UnifiPresenceDevice icons to Domoticz")
            Domoticz.Image("udevice.zip").Create()

        Domoticz.Log("Number of icons loaded = " + str(len(Images)))
        for item in Images:
            Domoticz.Log(strName+"Items = "+str(item))
            Domoticz.Log(strName+"Icon " + str(Images[item].ID) + " Name = " + Images[item].Name)

        self.login()
        if self._current_status_code == 200:
            self.create_devices()
            
            # Create table
            #     0           1         2            3         4
            # Device_Name | MAC_ID | Unit_Number | State | Last Online
            #   Test        1:1:1:1     50           Off      No
            #   Test                    50           Off      No
            #   Test                    50           On       Yes
            #   Test                    50           On       Yes
            #   Test                    50           Off      No
            device_mac=Parameters["Mode2"].split(",")
            w, h = 5, self.total_devices_count;
            self.Matrix = [[0 for x in range(w)] for y in range(h)]

            count = 0
            found_user = None
            for device in device_mac:
                device = device.strip()
                Device_Name, Device_Mac = device.split("=")
                self.Matrix[count][0] = Device_Name
                self.Matrix[count][1] = Device_Mac.lower()
                Device_Unit = None
                self.Matrix[count][3] = "Off"
                self.Matrix[count][4] = "No"
                found_device = Device_Name
                for dv in Devices:
                    # Find the unit number
                    search_device = Devices[dv].Name
                    position = search_device.find("-")+2
                    if Devices[dv].Name[position:] == found_device:
                        self.Matrix[count][2] = Devices[dv].Unit
                        count = count + 1
            
        Domoticz.Heartbeat(5)

    def onStop(self):
        strName = "onStop: "
        Domoticz.Debug(strName+"Plugin is stopping.")
        self.logout()

    def onConnect(self, Connection, Status, Description):
        strName = "onConnect: "
        Domoticz.Debug(strName+"called")
        Domoticz.Debug(strName+"Connection = "+str(Connection))
        Domoticz.Debug(strName+"Status = "+str(Status))
        Domoticz.Debug(strName+"Description = "+str(Description))

    def onMessage(self, Connection, Data):
        strName = "onMessage: "
        Domoticz.Debug(strName+"called")
        DumpHTTPResponseToLog(Data)
        Domoticz.Debug(strName+"Data = " +str(Data))
        strData = Data["Data"].decode("utf-8", "ignore")
        status = int(Data["Status"])

        if (self._current_status_code == 200):
            unifiResponse = json.loads(strData)
            Domoticz.Debug(strName+"Retrieved following json: "+json.dumps(unifiResponse))
            self.onHeartbeat()

    def onCommand(self, Unit, Command, Level, Hue):
        strName = "onCommand: "
        Domoticz.Log(strName+"called for Unit " + str(Unit) + ": Parameter '" + str(Command) + "', Level: " + str(Level))

        self.onHeartbeat()


    def onNotification(self, Name, Subject, Text, Status, Priority, Sound, ImageFile):
        strName = "onNotification: "
        Domoticz.Debug(strName+"called")
        Domoticz.Log(strName+"Notification: " + Name + "," + Subject + "," + Text + "," + Status + "," + str(Priority) + "," + Sound + "," + ImageFile)

    def onDisconnect(self, Connection):
        strName = "onDisconnect: "
        Domoticz.Debug(strName+"called")

    def onHeartbeat(self):
        strName = "onHeartbeat: "
        Domoticz.Debug(strName+"called")
        if self.versionCheck is True:
            if (self._current_status_code == None) or (self._current_status_code == 401) or (self._current_status_code == 404) or (self._current_status_code != 200):
                Domoticz.Log(strName+'Attempting to reconnect Unifi Controller')
                self.login()

            if self._current_status_code == 200:
                Domoticz.Debug(strName+'Requesting Unifi Controller details')
                self.request_details()
                if self._current_status_code == 200:
                    self.request_online_phones()


    def getCookies(cookie_jar, domain):
        cookie_dict = cookie_jar.get_dict(domain=domain)
        found = ['%s=%s' % (name, value) for (name, value) in cookie_dict.items()]
        return ';'.join(found)

    def login(self):
        strName = "login: "
        Domoticz.Debug(strName+"called")
        """
        Log the user in
        :return: None
        api url for dreammachine pro: /api/auth/login
        api url for other: /api/login
        """
        if Parameters["Mode4"] == "unificontroller":
            self._session.headers.update({'Content-Type' : 'application/json'})
            self._session.headers.update({'Connection' : 'keep-alive'})
            r = self._session.post("{}/api/login".format(self._baseurl), data=json.dumps(self._login_data), verify=self._verify_ssl, timeout=4000)
            controller = "Unifi Controller"
        elif Parameters["Mode4"] == "dreammachinepro":
            self._session.headers.update({'Content-Type' : 'application/json'})
            self._session.headers.update({'Connection' : 'keep-alive'})
            r = self._session.post("{}/api/auth/login".format(self._baseurl), data=json.dumps(self._login_data), verify=self._verify_ssl, timeout=4000)
            if 'X-CSRF-Token' in r.headers:
                self._session.headers.update({'X-CSRF-Token': r.headers['X-CSRF-Token']})
                Domoticz.Log(strName+"X-SCRF-Token found and added to header")
            controller = "Dream Machine Pro"
        else:
            Domoticz.Error(strName+"Check configuration!!")

        #r = self._session.post("{}{}".format(self._baseurl,url_api_login), data=json.dumps(self._login_data), verify=self._verify_ssl)

        self._current_status_code = r.status_code
        if self._current_status_code == 200:
            Domoticz.Log(strName+"Login successful into "+controller)
            self._Cookies = r.cookies
            self._lastloginfailed = False
        elif self._current_status_code == 400:
            Domoticz.Error(strName+"Failed to log in to api ("+controller+") with provided credentials ("+str(self._current_status_code)+")")
        else:
            if self._lastloginfailed:
                Domoticz.Error(strName+"Failed to login to the "+controller+" with errorcode "+str(self._current_status_code))
                self._current_status_code = 999
            else:
                Domoticz.Log(strName+"First attempt failed to login to the "+controller+" with errorcode "+str(self._current_status_code))
                self._lastloginfailed = True
                self._current_status_code = 999

    def logout(self):
        strName = "logout: "
        """
        Log the user out
        :return: None
        """
        if self._current_status_code == 200:
            if Parameters["Mode4"] == "unificontroller":
                self._session.post("{}/logout".format(self._baseurl, verify=self._verify_ssl))
            elif Parameters["Mode4"] == "dreammachinepro":
                #self._session.post("{}/proxy/network/logout".format(self._baseurl, verify=self._verify_ssl))
                self._session.post("{}/api/auth".format(self._baseurl, verify=self._verify_ssl))
            else:
                Domoticz.Error("Check configuration!!")
            Domoticz.Log(strName+"Logout of the Unifi API")
            self._session.close()
            self._current_status_code = 999
            self._timeout_timer = None

    def request_online_devices(self):
        strName = "request_online_phones: "
        if Parameters["Mode4"] == "unificontroller":
            r = self._session.get("{}/api/s/{}/stat/sta".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}", cookies=self._Cookies)
        elif Parameters["Mode4"] == "dreammachinepro":
            r = self._session.get("{}/proxy/network/api/s/{}/stat/sta".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}", cookies=self._Cookies)
        else:
            Domoticz.Error("Check configuration!!")

        self._current_status_code = r.status_code

        if self._current_status_code == 200:
            data = r.json()['data']

            for item in data:
                Domoticz.Debug(strName+"Json Data (device) = " + str(item))
                device_mac=Parameters["Mode2"].split(",")
                found_mac = 0
                found_mac_address = None
                found_user = None
                for device in device_mac:
                    device_unit = None
                    device = device.strip()
                    device_name, mac_id = device.split("=")
                    device_name = device_name.strip()
                    mac_id = mac_id.strip().lower()
                    if str(item['mac']) == mac_id:
                        # Found MAC address in API output
                        for x in range(self.total_devices_count):
                            if self.Matrix[x][1] == mac_id:
                                self.Matrix[x][5] = "Yes"
            self.ProcessDevices()
        elif self._current_status_code == 401:
            Domoticz.Log(strName+"Invalid login, or login has expired")
            self.login()
        elif self._current_status_code == 404:
            Domoticz.Log(strName+"Invalid login, or login has expired")
            self.login()


    def block_device(self, device_name, mac):
        strName = "block_device: "
        self._block_data['cmd'] ='block-sta'
        self._block_data['mac'] = mac
        if Parameters["Mode4"] == "unificontroller":
            r = self._session.post("{}/api/s/{}/cmd/stamgr".format(self._baseurl, self._site, verify=self._verify_ssl), data=json.dumps(self._block_data), verify=self._verify_ssl).status_code
        elif Parameters["Mode4"] == "dreammachinepro":
            r = self._session.post("{}/proxy/network/api/s/{}/cmd/stamgr".format(self._baseurl, self._site, verify=self._verify_ssl), data=json.dumps(self._block_data), verify=self._verify_ssl).status_code
        else:
            Domoticz.Error("Check configuration!!")

        if r == 200:
            Domoticz.Log(strName+"Blocked '" + device_name + "' with mac address " + mac)
        elif r == 401:
            Domoticz.Log(strName+"Invalid login, or login has expired")
            self.login()
        elif r == 404:
            Domoticz.Log(strName+"Invalid login, or login has expired")
            self.login()


    def unblock_device(self, device_name, mac, unit):
        strName = "unblock_phone: "
        self._block_data['cmd'] ='unblock-sta'
        self._block_data['mac'] = mac
        if Parameters["Mode4"] == "unificontroller":
            r = self._session.post("{}/api/s/{}/cmd/stamgr".format(self._baseurl, self._site, verify=self._verify_ssl), data=json.dumps(self._block_data), verify=self._verify_ssl).status_code
        elif Parameters["Mode4"] == "dreammachinepro":
            r = self._session.post("{}/proxy/network/api/s/{}/cmd/stamgr".format(self._baseurl, self._site, verify=self._verify_ssl), data=json.dumps(self._block_data), verify=self._verify_ssl).status_code
        else:
            Domoticz.Error("Check configuration!!")

        if  r == 200:
            UpdateDevice(unit, 0, "Off")
            Domoticz.Log(strName+"Unblocked '" + device_name + "' with mac address " + mac)
        elif r == 401:
            Domoticz.Log(strName+"Invalid login, or login has expired")
            self.login()
        elif r == 404:
            Domoticz.Log(strName+"Invalid login, or login has expired")
            self.login()


    def ProcessDevices(self):
        strName = "ProcessDevices: "
        if Parameters["Mode5"] == "No":
            svalueOn = "On"
            nvalueOn = 1
            svalueOff = "Off"
            nvalueOff = 0
        else:
            svalueOn = "30" # 30 = ON
            nvalueOn = 30
            svalueOff = "0"
            nvalueOff = 0  # 0 = OFF
        for x in range(self.total_devices_count):
            if self.Matrix[x][3] == "Off" and self.Matrix[x][4] == "No" and self.Matrix[x][5] == "No":
                self.Matrix[x][4] = self.Matrix[x][5]
                if Devices[self.Matrix[x][2]].nValue != 0:
                    UpdateDevice(self.Matrix[x][2], nvalueOff, svalueOff)
            elif self.Matrix[x][3] == "Off" and self.Matrix[x][4] == "No" and self.Matrix[x][5] == "Yes":
                Domoticz.Log(strName+"Phone '"+self.Matrix[x][0]+"' connected to the Unifi Controller")
                self.Matrix[x][3] = "On"
                self.Matrix[x][4] = self.Matrix[x][5]
                self.Matrix[x][5] = "No"
                UpdateDevice(self.Matrix[x][2], nvalueOn, svalueOn)
            elif self.Matrix[x][3] == "Off" and self.Matrix[x][4] == "Yes" and self.Matrix[x][5] == "Yes":
                Domoticz.Log(strName+"Phone '"+self.Matrix[x][0]+"' connected to the Unifi Controller")
                self.Matrix[x][3] = "On"
                self.Matrix[x][4] = self.Matrix[x][5]
                self.Matrix[x][5] = "No"
                UpdateDevice(self.Matrix[x][2], nvalueOn, svalueOn)
            elif self.Matrix[x][3] == "On" and self.Matrix[x][4] == "Yes" and self.Matrix[x][5] == "No":
                Domoticz.Log(strName+"Phone '"+self.Matrix[x][0]+"' disconnected from the Unifi Controller")
                self.Matrix[x][3] = "Off"
                self.Matrix[x][4] = self.Matrix[x][5]
                self.Matrix[x][5] = "No"
                UpdateDevice(self.Matrix[x][2], nvalueOff, svalueOff)
            elif self.Matrix[x][3] == "On" and self.Matrix[x][4] == "Yes" and self.Matrix[x][5] == "Yes":
                Domoticz.Debug(strName+"Phone '"+self.Matrix[x][0]+"' still connected to the Unifi Controller")
                self.Matrix[x][3] = "On"
                self.Matrix[x][4] = self.Matrix[x][5]
                self.Matrix[x][5] = "No"
                UpdateDevice(self.Matrix[x][2], nvalueOn, svalueOn)

        count = 0
        Domoticz.Debug(strName+"NU self.total_devices_count - "+str(self.total_devices_count))
        for x in range(self.total_devices_count):
            Domoticz.Debug(strName+" "+str(x)+" Phone Naam = "+str(self.Matrix[x][0])+" | "+str(self.Matrix[x][1])+" | "+str(self.Matrix[x][2])+" | "+str(self.Matrix[x][3])+" | "+str(self.Matrix[x][4])+" | "+str(self.Matrix[x][5]))
            if self.Matrix[x][3] == "On":
                count = count + 1
        if self._total_phones_active_before != count:
            Domoticz.Log(strName+"Total Phones connected = "+str(count))
        self._total_phones_active_before = count

        if count > 0:
            UpdateDevice(self.UNIFI_ANYONE_HOME_UNIT, 1, "On")
        else:
            UpdateDevice(self.UNIFI_ANYONE_HOME_UNIT, 0, "Off")

    def setVersionCheck(self, value, note):
        strName = "setVersionCheck - "
        if value is True:
            if self.versionCheck is not False:
                self.versionCheck = True
                Domoticz.Log(strName+"Plugin allowed to start (triggered by: "+note+")")
        elif value is False:
            self.versionCheck = False
            Domoticz.Error(strName+"Plugin NOT allowed to start (triggered by: "+note+")")

 
    def create_devices(self):
        strName = "create_devices: "
        # create devices
        device_mac=Parameters["Mode2"].split(",")

        found_device = False
        count_device = 0
        for device in device_mac:
            device = device.strip()
            device_name, mac_id = device.split("=")
            device_name = device_name.strip()
            mac_id = mac_id.strip().lower()
            try:
                for item in Devices:
                    devName = Devices[item].Name
                    position = devName.find("-")+2
                    if Devices[item].Name[position:] == phone_name:
                        Domoticz.Log(strName+"Found device to monitor from configuration = "+device)
                        found_device = True
                        count_device = count_device + 1
                if found_device == False:
                    new_unit_device = find_available_unit_device()
                    if Parameters["Mode5"] == "Yes":
                        Options = {"LevelActions": "||||",
                        "LevelNames": "Off|Block|Unblock|On",
                        "LevelOffHidden": "false",
                        "SelectorStyle": "0"}
                        Domoticz.Device(Name=device_name, Unit=new_unit_device, TypeName="Selector Switch", Switchtype=18, Used=1, Options=Options, Image=Images['UnifiPresenceOverride'].ID).Create()
                        count_device = count_device + 1
                    else:
                        Domoticz.Device(Name=device_name, Unit=new_unit_device, TypeName="Switch", Used=1, Image=Images['UnifiPresenceOverride'].ID).Create()
                        count_device = count_device + 1

            except:
                Domoticz.Error(strName+"Invalid device settings. (" +device+")")

            # calculate total devices
            self.total_devices_count = count_device

global _plugin
_plugin = BasePlugin()

def onStart():
    global _plugin
    _plugin.onStart()

def onStop():
    global _plugin
    _plugin.onStop()

def onConnect(Connection, Status, Description):
    global _plugin
    _plugin.onConnect(Connection, Status, Description)

def onMessage(Connection, Data):
    global _plugin
    _plugin.onMessage(Connection, Data)

def onCommand(Unit, Command, Level, Hue):
    global _plugin
    _plugin.onCommand(Unit, Command, Level, Hue)

def onNotification(Name, Subject, Text, Status, Priority, Sound, ImageFile):
    global _plugin
    _plugin.onNotification(Name, Subject, Text, Status, Priority, Sound, ImageFile)

def onDisconnect(Connection):
    global _plugin
    _plugin.onDisconnect(Connection)

def onHeartbeat():
    global _plugin
    _plugin.onHeartbeat()

def LogMessage(Message):
    strName = "LogMessage: "
    if Parameters["Mode6"] == "File":
        f = open(Parameters["HomeFolder"]+"http.html","w")
        f.write(Message)
        f.close()
        Domoticz.Debug(strName+"File written")

def DumpHTTPResponseToLog(httpResp, level=0):
    strName = "DumpHTTPResponseToLog: "
    if (level==0): Domoticz.Debug(strName+"HTTP Details ("+str(len(httpResp))+"):")
    indentStr = ""
    for x in range(level):
        indentStr += "----"
    if isinstance(httpResp, dict):
        for x in httpResp:
            if not isinstance(httpResp[x], dict) and not isinstance(httpResp[x], list):
                Domoticz.Debug(strName+indentStr + ">'" + x + "':'" + str(httpResp[x]) + "'")
            else:
                Domoticz.Debug(strName+indentStr + ">'" + x + "':")
                DumpHTTPResponseToLog(httpResp[x], level+1)
    elif isinstance(httpResp, list):
        for x in httpResp:
            Domoticz.Debug(strName+indentStr + "['" + x + "']")
    else:
        Domoticz.Debug(strName+indentStr + ">'" + x + "':'" + str(httpResp[x]) + "'")

def UpdateDevice(Unit, nValue, sValue, Image=None):
    strName = "UpdateDevice: "
    # Make sure that the Domoticz device still exists (they can be deleted) before updating it
    if (Unit in Devices):
        if (Devices[Unit].nValue != nValue) or (Devices[Unit].sValue != sValue) or ((Image != None) and (Image != Devices[Unit].Image)):
            if (Image != None) and (Image != Devices[Unit].Image):
                Devices[Unit].Update(nValue=nValue, sValue=str(sValue), Image=Image)
                Domoticz.Log(strName+"Update "+str(nValue)+":'"+str(sValue)+"' ("+Devices[Unit].Name+") Image="+str(Image))
            else:
                Devices[Unit].Update(nValue=nValue, sValue=str(sValue))
                Domoticz.Log(strName+"Update "+str(nValue)+":'"+str(sValue)+"' ("+Devices[Unit].Name+")")

    # Generic helper functions
def DumpConfigToLog():
    strName = "DumpConfigToLog: "
    for x in Parameters:
        if Parameters[x] != "":
            Domoticz.Debug(strName+"'" + x + "':'" + str(Parameters[x]) + "'")
    Domoticz.Debug("Device count: " + str(len(Devices)))
    for x in Devices:
        Domoticz.Debug(strName+"Device:           " + str(x) + " - " + str(Devices[x]))
        Domoticz.Debug(strName+"Device ID:       '" + str(Devices[x].ID) + "'")
        Domoticz.Debug(strName+"Device Name:     '" + Devices[x].Name + "'")
        Domoticz.Debug(strName+"Device nValue:    " + str(Devices[x].nValue))
        Domoticz.Debug(strName+"Device sValue:   '" + Devices[x].sValue + "'")
        Domoticz.Debug(strName+"Device LastLevel: " + str(Devices[x].LastLevel))
    return

def find_available_unit_device():
    for num in range(1,240):
        if num not in Devices:
            return num
    return None

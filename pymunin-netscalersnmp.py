#!/usr/bin/python
"""netscalersnmp - Munin Plugin to monitor Netscaler loadbalancer via snmtp.

Requirements
  - The working snmpwalk command for the netscaller.
    
Wild Card Plugin - No


Multigraph Plugin - Graph Structure
   - multicast_pkts
   - unicast_pkts
   - total_octets
   - nsHttpStatsGroup
   - vserverTable

   
Environment Variables

  host:          snmp Host. (Default: 127.0.0.1)

  community:          Community string
  
  include_graphs: Comma separated list of enabled graphs.
                  (All graphs enabled by default.)
  exclude_graphs: Comma separated list of disabled graphs.


  Example:

"""
# Munin  - Magic Markers
#%# family=manual
#%# capabilities=noautoconf nosuggest

import sys, os
from pymunin import MuninGraph, MuninPlugin, muninMain
from collections import defaultdict


__author__ = "Petros Rizos"
__maintainer__ = "Petros Rizos"
__email__ = "petros.rizos@gmail.com"
__status__ = "Development"


class MuninTomcatPlugin(MuninPlugin):
    """Multigraph Munin Plugin for monitoring Netscaler snmp.

    """
    plugin_name = 'netscalersnmp'
    isMultigraph = True

    def __init__(self, argv=(), env={}, debug=False):
        """Populate Munin Plugin with MuninGraph instances.
        
        @param argv:  List of command line arguments.
        @param env:   Dictionary of environment variables.
        @param debug: Print debugging messages if True. (Default: False)
        
        """
        MuninPlugin.__init__(self, argv, env, debug)
        
        self.envRegisterFilter('ports', '^\d+$')
        
        self._host = self.envGet('host')
        self._community = self.envGet('community')
        self._name_full = []
        self._data_full = []
        self._protocol_name = []
        self._variable_name = []
        self._variable_type = []
        self._variable_data = []
        
        #retrieving values to enumerate counters
        self.retrieveVals()
        
        #Start of multicast graphing
        if self.graphEnabled('multicast_pkts'):
            graph = MuninGraph('Multicast packets', 'Netscaler',
                info='Multicast packets (packets).',
                args='--base 1000 --lower-limit 0')
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifInMulticastPkts.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifOutMulticastPkts.1')
            
            try:
                if_count = 1
                for pointer in self.my_range(in_pointer,in_pointer+9,1):
                    graph.addField('in%s'%(if_count), 'in%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets out (packets) by %s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
                
                if_count = 1
                for pointer in self.my_range(out_pointer,out_pointer+9,1):
                    graph.addField('out%s'%(if_count), 'out%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets in (packets) by%s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
            except:
                pass
            self.appendGraph('multicast_pkts', graph)
#          
        #Start of Unicast graphing
        if self.graphEnabled('unicast_pkts'):
            graph = MuninGraph('Unicast packets', 'Netscaler',
                info='Unicast packets (excluding multicast/broadcast).',
                args='--base 1000 --lower-limit 0')
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifInUcastPkts.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifOutUcastPkts.1')
            
            try:
                if_count = 1
                for pointer in self.my_range(in_pointer,in_pointer+9,1):
                    graph.addField('in%s'%(if_count), 'in%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets out (packets) by %s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
                
                if_count = 1
                for pointer in self.my_range(out_pointer,out_pointer+9,1):
                    graph.addField('out%s'%(if_count), 'out%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets in (packets) by%s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
            except:
                pass
            self.appendGraph('unicast_pkts', graph)
            
        #Start of broadcast graphing
        if self.graphEnabled('broadcast_pkts'):
            graph = MuninGraph('Broadcast packets', 'Netscaler',
                info='Broadcast packets (Packets).',
                args='--base 1000 --lower-limit 0')
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifInBroadcastPkts.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifOutBroadcastPkts.1')
            
            try:
                if_count = 1
                for pointer in self.my_range(in_pointer,in_pointer+9,1):
                    graph.addField('in%s'%(if_count), 'in%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets out (packets) by %s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
                
                if_count = 1
                for pointer in self.my_range(out_pointer,out_pointer+9,1):
                    graph.addField('out%s'%(if_count), 'out%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets in (packets) by%s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
            except:
                pass
            self.appendGraph('broadcast_pkts', graph)
        
        #Start of octets graphing    
        if self.graphEnabled('total_octets'):
            graph = MuninGraph('Total octets', 'Netscaler',
                info='Total number of octects (octets).',
                args='--base 1000 --lower-limit 0')
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifHCInOctets.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifHCOutOctets.1')
            
            try:
                if_count = 1
                for pointer in self.my_range(in_pointer,in_pointer+9,1):
                    graph.addField('in%s'%(if_count), 'in%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets out (packets) by %s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
                
                if_count = 1
                for pointer in self.my_range(out_pointer,out_pointer+9,1):
                    graph.addField('out%s'%(if_count), 'out%s'%(if_count), draw='LINE1', type='COUNTER',
                               info="Packets in (packets) by%s"%(self._variable_name[pointer]))
                    if_count = if_count + 1
            except:
                pass
            self.appendGraph('total_octets', graph)
            
        #Start of http statistics graphing
        if self.graphEnabled('nsHttpStatsGroup'):
            graph = MuninGraph('HTTP statistics', 'Netscaler',
                info='Total number transactions (counter).',
                args='--base 1000 --lower-limit 0')
               
            try:

                graph.addField('httpTotGets', 'httpTotGets', draw='LINE1', type='COUNTER',
                           info="HTTP requests received using the GET method.")
                graph.addField('httpTotPosts', 'httpTotPosts', draw='LINE1', type='COUNTER',
                           info="HTTP requests received using the POST method.")
                graph.addField('httpTotOthers', 'httpTotOthers', draw='LINE1', type='COUNTER',
                           info="HTTP requests received using methods other than GET and POST. Some of the other well-defined HTTP methods are HEAD, PUT, DELETE, OPTIONS, and TRACE. User-defined methods are also allowed.")
                graph.addField('httpTot10Requests', 'httpTot10Requests', draw='LINE1', type='COUNTER',
                           info="HTTP/1.0 requests received.")
                graph.addField('httpTotResponses', 'httpTotResponses', draw='LINE1', type='COUNTER',
                           info="HTTP responses sent including HTTP/1.0 and HTTP/1.1 responses.")
                graph.addField('httpTot10Responses', 'httpTot10Responses', draw='LINE1', type='COUNTER',
                           info="HTTP/1.0 responses sent.")
                graph.addField('httpErrServerBusy', 'httpErrServerBusy', draw='LINE1', type='COUNTER',
                           info="Error responses received. Some of the error responses are: 500 Internal Server Error 501 Not Implemented 502 Bad Gateway 503 Service Unavailable 504 Gateway Timeout 505 HTTP Version Not Supported")
                graph.addField('httpErrLargeContent', 'httpErrLargeContent', draw='LINE1', type='COUNTER',
                           info="Large or invalid requests and responses received.")
                
            except:
                pass
            self.appendGraph('nsHttpStatsGroup', graph)
            
            
        #Start of Vpool graphing   
        if self.graphEnabled('vserverTable'):
            
            vpool_names = self.dict_snmpbulkwalk('1.3.6.1.4.1.5951.4.1.3.1.1.1',self._community,self._host)#get names
         
          
            graph = MuninGraph('vserver Table clients', 'Netscaler',
                info='Number of connections',
                args='--base 1000 --lower-limit 0')
            
            
            for vpool in vpool_names['variable_data']:
                graph.addField(vpool, vpool, draw='LINE1', type='GAUGE',
                            info="The number of current client connections by %s"%(vpool))
                
            self.appendGraph('vserverTable_client', graph)
        
            graph = MuninGraph('vserver Table servers', 'Netscaler',
                info='Number of connections',
                args='--base 1000 --lower-limit 0')    
        
        
            for vpool in vpool_names['variable_data']:
                graph.addField(vpool, vpool, draw='LINE1', type='GAUGE',
                            info="The number of current connections to the real servers behind the vserver by %s"%(vpool))
                
            self.appendGraph('vserverTable_server', graph)
           
           


            
        
    def retrieveVals(self):
        """Retrieve values for graphs."""
        #For HTTP data adds it to the primary snmp data lists
        self.add_snmpwalk('1.3.6.1.4.1.5951.4.1.1.48',self._community,self._host)
        #Grabbing default snmp data into primary pool
        self.add_snmpwalk('',self._community,self._host)

        
        if self.hasGraph('multicast_pkts'):
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifInMulticastPkts.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifOutMulticastPkts.1')
            
            if_count = 1
            for pointer in self.my_range(in_pointer,in_pointer+9,1):
                self.setGraphVal('multicast_pkts', 'in%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1
            
            if_count = 1
            for pointer in self.my_range(out_pointer,out_pointer+9,1):
                self.setGraphVal('multicast_pkts', 'out%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1

        if self.hasGraph('unicast_pkts'):
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifInUcastPkts.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifOutUcastPkts.1')
            
            if_count = 1
            for pointer in self.my_range(in_pointer,in_pointer+9,1):
                self.setGraphVal('unicast_pkts', 'in%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1
            
            if_count = 1
            for pointer in self.my_range(out_pointer,out_pointer+9,1):
                self.setGraphVal('unicast_pkts', 'out%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1
                
        if self.hasGraph('broadcast_pkts'):
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifInBroadcastPkts.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifOutBroadcastPkts.1')
            
            if_count = 1
            for pointer in self.my_range(in_pointer,in_pointer+9,1):
                self.setGraphVal('broadcast_pkts', 'in%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1
            
            if_count = 1
            for pointer in self.my_range(out_pointer,out_pointer+9,1):
                self.setGraphVal('broadcast_pkts', 'out%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1

        if self.hasGraph('total_octets'):
            
            in_pointer = self._broadcast_pkts_in_pointer = self._variable_name.index('ifHCInOctets.1')
            out_pointer = self._broadcast_pkts_out_pointer = self._variable_name.index('ifHCOutOctets.1')
            
            if_count = 1
            for pointer in self.my_range(in_pointer,in_pointer+9,1):
                self.setGraphVal('total_octets', 'in%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1
            
            if_count = 1
            for pointer in self.my_range(out_pointer,out_pointer+9,1):
                self.setGraphVal('total_octets', 'out%s'%(if_count), self._variable_data[pointer])
                if_count = if_count + 1
                
        if self.hasGraph('nsHttpStatsGroup'):
            
            httpTotGets_pointer =  self._variable_name.index('enterprises.5951.4.1.1.48.45.0')
            httpTotPosts_pointer =  self._variable_name.index('enterprises.5951.4.1.1.48.46.0')
            httpTotOthers_pointer =  self._variable_name.index('enterprises.5951.4.1.1.48.47.0')
            httpTot10Requests_pointer = self._variable_name.index('enterprises.5951.4.1.1.48.52.0')
            httpTotResponses_pointer = self._variable_name.index('enterprises.5951.4.1.1.48.53.0')
            httpTot10Responses_pointer = self._variable_name.index('enterprises.5951.4.1.1.48.54.0')
            httpErrServerBusy_pointer = self._variable_name.index('enterprises.5951.4.1.1.48.61.0')
            httpErrLargeContent_pointer = self._variable_name.index('enterprises.5951.4.1.1.48.64.0')
            
            
            
            self.setGraphVal('nsHttpStatsGroup', 'httpTotGets', self._variable_data[httpTotGets_pointer])
            self.setGraphVal('nsHttpStatsGroup', 'httpTotPosts', self._variable_data[httpTotPosts_pointer])
            self.setGraphVal('nsHttpStatsGroup', 'httpTotOthers', self._variable_data[httpTotOthers_pointer])
            self.setGraphVal('nsHttpStatsGroup', 'httpTot10Requests', self._variable_data[httpTot10Requests_pointer])
            self.setGraphVal('nsHttpStatsGroup', 'httpTotResponses', self._variable_data[httpTotResponses_pointer])
            self.setGraphVal('nsHttpStatsGroup', 'httpTot10Responses', self._variable_data[httpTot10Responses_pointer])
            self.setGraphVal('nsHttpStatsGroup', 'httpErrServerBusy', self._variable_data[httpErrServerBusy_pointer])
            self.setGraphVal('nsHttpStatsGroup', 'httpErrLargeContent', self._variable_data[httpErrLargeContent_pointer])

        if self.hasGraph('vserverTable_client'):
            
            vpool_names = self.dict_snmpbulkwalk('1.3.6.1.4.1.5951.4.1.3.1.1.1',self._community,self._host)#get names
            client_connections = self.dict_snmpbulkwalk('1.3.6.1.4.1.5951.4.1.3.1.1.7',self._community,self._host)
            server_connections = self.dict_snmpbulkwalk('1.3.6.1.4.1.5951.4.1.3.1.1.7',self._community,self._host)
                    
            for value, vpool in zip(client_connections['variable_data'],vpool_names['variable_data']):
                self.setGraphVal('vserverTable_client', vpool, value)
            
            for value, vpool in zip(server_connections['variable_data'],vpool_names['variable_data']):
                self.setGraphVal('vserverTable_server', vpool, value)


    def my_range(self, start, end, step):
        while start<=end:
            yield start
            start += step
    
    def add_snmpwalk(self,oid,community,host):
        #CommunityStringHere
        data = os.popen("snmpwalk -c %s -v 2c %s %s"%(community,host,oid),'r')
        lines = data.readlines()
        
        for line in lines:
            try:
                line = line.split("=")
                self._name_full.append(line[0])
                self._data_full.append(line[1])
            except:
                pass
        
        for name, data in zip(self._name_full, self._data_full):
            name = name.split("::")
            data = data.split(":")
            try:
                self._protocol_name.append(name[0].strip())
                self._variable_name.append(name[1].strip())
                self._variable_type.append(data[0].strip())
                self._variable_data.append(data[1].strip())
            except:
                pass        
    
    def dict_snmpbulkwalk(self,oid,community,host):
        name_full = []
        data_full = []
        dic = defaultdict(list)
        data = os.popen("snmpwalk -c %s -v 2c %s %s"%(community,host,oid),'r')
        lines = data.readlines()
        
        for line in lines:
            line = line.split("=")
            name_full.append(line[0])
            data_full.append(line[1])
            
        for name, data in zip(name_full, data_full):
            name = name.split("::")
            data = data.split(":") 
            dic['protocol_name'].append(name[0].strip().strip("\"").replace('.','').replace('-','').replace('_',''))
            dic['variable_name'].append(name[1].strip().strip("\"").replace('.','').replace('-','').replace('_',''))
            dic['variable_type'].append(data[0].strip().strip("\"").replace('.','').replace('-','').replace('_',''))
            dic['variable_data'].append(data[1].strip().strip("\"").replace('.','').replace('-','').replace('_',''))
            
        return dic


def main():
    sys.exit(muninMain(MuninTomcatPlugin))


if __name__ == "__main__":
    main()

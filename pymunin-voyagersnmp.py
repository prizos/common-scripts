#!/usr/bin/python
"""pyvoyager - Munin Plugin to monitor voyager servers

Requirements
  - A working snmp for the voyager stats
    
Wild Card Plugin - No


Multigraph Plugin - Graph Structure
   - All SNMP data

   
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


class MuninVoyagerPlugin(MuninPlugin):
    """Multigraph Munin Plugin for monitoring Voyager snmp.

    """
    plugin_name = 'voyagersnmp'
    isMultigraph = True

    def __init__(self, argv=(), env={}, debug=False):
        """Populate Munin Plugin with MuninGraph instances.
        
        @param argv:  List of command line arguments.
        @param env:   Dictionary of environment variables.
        @param debug: Print debugging messages if True. (Default: False)
        
        """
        MuninPlugin.__init__(self, argv, env, debug)
        
        self.envRegisterFilter('ports', '^\d+$')
        
        self._host = self.envGet('hostname')
        self._community = self.envGet('community')
        self._name_full = []
        self._data_full = []
        self._protocol_name = []
        self._variable_name = []
        self._variable_type = []
        self._variable_data = []
        
        self._names_dic = self.dict_snmpbulkwalk('1.3.6.1.4.1.8384.1001.1.1.205',self._community,self._host)
        self._types_dic = self.dict_snmpbulkwalk('1.3.6.1.4.1.8384.1001.1.1.206',self._community,self._host)
        self._values_dic = self.dict_snmpbulkwalk('1.3.6.1.4.1.8384.1001.1.1.207',self._community,self._host)
        
            
        #Start of voyager graphing   
        if self.graphEnabled('vserverTable'):
            
            for name in self._names_dic['variable_data']:
                
                graph = MuninGraph('Voyager stats for %s' %(name), 'Voyager',
                info='%s'%(name),
                args='--base 1000 --lower-limit 0')
                
                
                graph.addField(name, name, draw='LINESTACK1', type='GAUGE',
                            info="Counts the %s field"%(name))
                
                self.appendGraph('%s'%(name), graph)
           
       
    def retrieveVals(self):
        """Retrieve values for graphs."""
                    
        for value, name in zip(self._values_dic['variable_data'],self._names_dic['variable_data']):
            self.setGraphVal('%s'%(name), name, value)


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
            dic['protocol_name'].append(name[0].strip().strip("\"").replace('.','').replace('-','').replace('_','').replace('(','').replace(')','').replace(')',''))
            dic['variable_name'].append(name[1].strip().strip("\"").replace('.','').replace('-','').replace('_','').replace('(','').replace(')','').replace(')',''))
            dic['variable_type'].append(data[0].strip().strip("\"").replace('.','').replace('-','').replace('_','').replace('(','').replace(')','').replace(')',''))
            dic['variable_data'].append(data[1].strip().strip("\"").replace('.','').replace('-','').replace('_','').replace('(','').replace(')','').replace(')',''))
        
        #Hacked correction due to bad SNMP data from voyager
        for index in self.my_range(0,3,1):
            dic['protocol_name'].pop(index)
            dic['variable_name'].pop(index)
            dic['variable_type'].pop(index)
            dic['variable_data'].pop(index)

            
        return dic


def main():
    sys.exit(muninMain(MuninVoyagerPlugin))


if __name__ == "__main__":
    main()

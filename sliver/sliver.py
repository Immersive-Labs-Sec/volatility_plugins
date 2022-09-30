# Sliver
# Copyright (C) 2022 Kevin Breen, Eva Ilieva, Immersive Labs
# https://github.com/Immersive-Labs-Sec/volatility_plugins
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
import re
import struct
from typing import List

from volatility3.framework import constants, exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise


signatures = {
    'cs_config_start': """rule cobaltstrike_config
                                {
                                strings:
                                  $a = {2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C}
                                  $b = {69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B}
                                  //$c = {?? 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02}
                                condition:
                                  any of them
                                }"""
}



class Sliver(interfaces.plugins.PluginInterface):
    """Scans process memory for each process to identify Sliver artifacts"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.PluginRequirement(name = 'vadyarascan', plugin = vadyarascan.VadYaraScan, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]


    @classmethod
    def parse_result(self, rule, value):
        """Parse the config from the result"""

        # https://github.com/Te-k/cobaltstrike/blob/master/lib.py 
        # This helped me figure out how to walk the structs after XOR

        if value.startswith(b'././'):
            xor_key = 0x2e
        elif value.startswith(b'ihih'):
            xor_key = 105
        else:
            xor_key = None

        vollog.debug(f'Found XOR Key {xor_key}')
        if not xor_key:
            vollog.info("Unable to find config file")
            return None

        # XOR the raw values to get the config section
        data = bytearray([c ^ xor_key for c in value])

        vollog.debug(data)

        config = {}
        i = 0
        while i < len(data) - 8:
            if data[i] == 0 and data[i+1] == 0:
                break
            dec = struct.unpack(">HHH", data[i:i+6])
            if dec[0] == 1:
                v = struct.unpack(">H", data[i+6:i+8])[0]
                config["dns"] = ((v & 1) == 1)
                config["ssl"] = ((v & 8) == 8)
            else:
                if dec[0] in CONFIG_STRUCT.keys():
                    key = CONFIG_STRUCT[dec[0]]
                else:
                    vollog.debug("Unknown config command {}".format(dec[0]))
                    key = str(dec[0])
                if dec[1] == 1 and dec[2] == 2:
                    # Short
                    config[key] = struct.unpack(">H", data[i+6:i+8])[0]
                elif dec[1] == 2 and dec[2] == 4:
                    # Int
                    config[key] = struct.unpack(">I", data[i+6:i+10])[0]
                elif dec[1] == 3:
                    # Byte or string
                    v = data[i+6:i+6+dec[2]]
                    try:
                        config[key] = v.decode('utf-8').strip('\x00')
                    except UnicodeDecodeError:
                        config[key] = v
            # Add size + header
            i += dec[2] + 6

        vollog.debug(config)
        return config

    def _generator(self, procs):

        # Compile the list of rules
        rules = yara.compile(sources = signatures)

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            vollog.debug(f'Scanning Process {process_name}\n')

            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            layer = self.context.layers[proc_layer_name]

            # Run the yara scan with our collection of rules. The offset is the important part here. 
            for offset, rule_name, name, value in layer.scan(context = self.context,
                                                             scanner = yarascan.YaraScanner(rules = rules),
                                                             sections = vadyarascan.VadYaraScan.get_vad_maps(proc)):

                if rule_name == 'cobaltstrike_config':
                    # Read 1024 bytes from the layer at the offset and try to parse out some values. 
                    config = self.parse_result(rule_name, layer.read(offset, 3096, False))
                    yield (0, (
                        proc.UniqueProcessId,
                        process_name,
                        config.get('port', 0),
                        config.get('sleeptime', 0),
                        config.get('jitter', 0),
                        config.get('server,get-uri', ''),
                        config.get('post-uri', ''),
                        config.get('spawnto_x86', ''),
                        config.get('spawnto_x64', ''),
                        config.get('pipename', ''),
                        config.get('license-id', 0),
                        ))


    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([
                ("PID", int),
                ("Process", str),
                ("Session Key", str),
                ("IP Address", str),
                ("Implant ECC Priv", str),
                ("Implant ECC Pub", str),
                ("Server ECC Pub", str),
            ],
            self._generator(
                pslist.PsList.list_processes(context = self.context,
                                             layer_name = kernel.layer_name,
                                             symbol_table = kernel.symbol_table_name,
                                             filter_func = filter_func)))

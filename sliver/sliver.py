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
from binascii import hexlify
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
    'cs_config_start': """rule sliver_session_keys
                                {
                                strings:
                                  $a = "WinHttpGetDefaultProxyConfiguration"
                                condition:
                                  any of them
                                }"""
}

# Matches b64 strings that are not empty values. 
b64_pattern = b'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
session_key_pattern = b'\x00\n (.{32})\x00'



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
                vollog.debug(f'Match at offset: {offset}')
                try:
                    session_raw_data = layer.read(offset, 248, False)
                except exceptions.InvalidAddressException as excp:
                    vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                    excp.layer_name))
                    continue

                vollog.debug(session_raw_data)

                if rule_name == 'sliver_session_keys':
                    session_key = re.findall(session_key_pattern, session_raw_data, re.DOTALL)

                    if len(session_key) >= 1:
                        session_key = session_key[0]
                    else:
                        session_key = 'Not Found in memory'

                    ecc_keys = re.findall(b64_pattern, session_raw_data)
                    if len(ecc_keys) == 4:
                        implant_private_key = ecc_keys[1]
                        implant_public_key = ecc_keys[2]
                        server_public_key = ecc_keys[3]

                        yield(
                            0, (
                                proc.UniqueProcessId,
                                process_name,
                                '192.168.1.1',
                                hexlify(session_key),
                                implant_private_key,
                                implant_public_key,
                                server_public_key
                            )
                        )



    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([
                ("PID", int),
                ("Process", str),
                ("IP Address", str),
                ("Session Key", bytes),
                ("Implant ECC Priv", bytes),
                ("Implant ECC Pub", bytes),
                ("Server ECC Pub", bytes),
            ],
            self._generator(
                pslist.PsList.list_processes(context = self.context,
                                             layer_name = kernel.layer_name,
                                             symbol_table = kernel.symbol_table_name,
                                             filter_func = filter_func)))

from multiprocessing import Pool
import os
import shutil

from ipv8.configuration import get_default_configuration
from ipv8.ipv8 import IPV8


def spawn(port):
    state_dir = os.path.join('processes', str(port))
    os.mkdir(state_dir)
    os.chdir(state_dir)

    configuration = get_default_configuration()
    configuration['port'] = port
    for key_desc in configuration['keys']:
        key_desc['file'] = None
    configuration['overlays'] = [overlay for overlay in configuration['overlays']
                                 if overlay['class'] != 'HiddenTunnelCommunity']
    ipv8 = IPV8(configuration)
    ipv8.start()


base_port = 28000
num_processes = 1000
if os.path.isdir('processes'):
    shutil.rmtree('processes')
os.mkdir('processes')

pool = Pool(num_processes)
pool.map(spawn, (base_port + i for i in xrange(num_processes)))

raw_input("Press Enter to continue...")

pool.terminate()
pool.join()

#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         sslyze_core.py
# Purpose:      Main module of SSLyze.
#
# Author:       aaron, alban
#
# Copyright:    2012 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

from time import time
from itertools import cycle
from multiprocessing import Process, JoinableQueue
from xml.etree.ElementTree import Element
from utils.OutputClasses import RegularOutput, NoOutput
from utils.OutputProcessors import XMLProcessor
import sys

from plugins import PluginsFinder

try:
    from utils.CommandLineParser import CommandLineParser, CommandLineParsingError
    from utils.ServersConnectivityTester import ServersConnectivityTester
except ImportError:
    print '\nERROR: Could not import nassl Python module. Did you clone SSLyze\'s repo ? \n' +\
    'Please download the right pre-compiled package as described in the README.'
    sys.exit()


PROJECT_VERSION = 'SSLyze v1.0 dev'
PROJECT_URL = "https://github.com/isecPartners/sslyze"
PROJECT_EMAIL = 'sslyze@isecpartners.com'
PROJECT_DESC = 'Fast and full-featured SSL scanner'

MAX_PROCESSES = 12
MIN_PROCESSES = 3


class WorkerProcess(Process):

    def __init__(self, priority_queue_in, queue_in, queue_out, available_commands, shared_settings):
        Process.__init__(self)
        self.priority_queue_in = priority_queue_in
        self.queue_in = queue_in
        self.queue_out = queue_out
        self.available_commands = available_commands
        self.shared_settings = shared_settings

    def run(self):
        """
        The process will first complete tasks it gets from self.queue_in.
        Once it gets notified that all the tasks have been completed,
        it terminates.
        """
        from plugins.PluginBase import PluginResult
        # Plugin classes are unpickled by the multiprocessing module
        # without state info. Need to assign shared_settings here
        for plugin_class in self.available_commands.itervalues():
            plugin_class._shared_settings = self.shared_settings

        # Start processing task in the priority queue first
        current_queue_in = self.priority_queue_in
        while True:

            task = current_queue_in.get() # Grab a task from queue_in
            if task is None: # All tasks have been completed
                current_queue_in.task_done()

                if (current_queue_in == self.priority_queue_in):
                    # All high priority tasks have been completed
                    current_queue_in = self.queue_in # Switch to low priority tasks
                    continue
                else:
                    # All the tasks have been completed
                    self.queue_out.put(None) # Pass on the sentinel to result_queue and exit
                    break

            (target, command, args) = task
            # Instantiate the proper plugin
            plugin_instance = self.available_commands[command]()

            try: # Process the task
                result = plugin_instance.process_task(target, command, args)
            except Exception as e: # Generate txt and xml results
                #raise
                txt_result = ['Unhandled exception when processing --' +
                              command + ': ', str(e.__class__.__module__) +
                              '.' + str(e.__class__.__name__) + ' - ' + str(e)]
                xml_result = Element(command, exception=txt_result[1])
                result = PluginResult(txt_result, xml_result)

            # Send the result to queue_out
            self.queue_out.put((target, command, result))
            current_queue_in.task_done()

        return

def main(start_time, output, target_list, shared_settings, sslyze_plugins, available_plugins, available_commands, return_result=False):
    output.available_plugins()
    for plugin in available_plugins:
        output.plugin_name(plugin.__name__)

    # Create result processors.
    result_processors = []
    if shared_settings['xml_file']:
        result_processors.append(XMLProcessor())

    #--PROCESSES INITIALIZATION--
    # Three processes per target from MIN_PROCESSES up to MAX_PROCESSES
    nb_processes = max(MIN_PROCESSES, min(MAX_PROCESSES, len(target_list)*3))
    if shared_settings['https_tunnel']:
        nb_processes = 1 # Let's not kill the proxy

    task_queue = JoinableQueue() # Processes get tasks from task_queue and
    result_queue = JoinableQueue() # put the result of each task in result_queue

    # Spawn a pool of processes, and pass them the queues
    process_list = []
    for _ in xrange(nb_processes):
        priority_queue = JoinableQueue() # Each process gets a priority queue
        p = WorkerProcess(priority_queue, task_queue, result_queue, available_commands, \
                          shared_settings)
        p.start()
        process_list.append((p, priority_queue)) # Keep track of each process and priority_queue

    #--TESTING SECTION--
    # Figure out which hosts are up and fill the task queue with work to do
    output.host_availability()

    targets_OK = []
    targets_ERR = []

    # Each server gets assigned a priority queue for aggressive commands
    # so that they're never run in parallel against this single server
    cycle_priority_queues = cycle(process_list)
    target_results = ServersConnectivityTester.test_server_list(target_list,
                                                                shared_settings)
    for target in target_results:
        if target is None:
            break # None is a sentinel here

        # Send tasks to worker processes
        targets_OK.append(target)
        (_, current_priority_queue) = cycle_priority_queues.next()

        for command in available_commands:
            if command in shared_settings:
                args = shared_settings[command]

                if command in sslyze_plugins.get_aggressive_commands():
                    # Aggressive commands should not be run in parallel against
                    # a given server so we use the priority queues to prevent this
                    current_priority_queue.put( (target, command, args) )
                else:
                    # Normal commands get put in the standard/shared queue
                    task_queue.put( (target, command, args) )

    for exception in target_results:
        targets_ERR.append(exception)

    output.server_connectivity_test(targets_OK, targets_ERR)

    # Put a 'None' sentinel in the queue to let the each process know when every
    # task has been completed
    for (proc, priority_queue) in process_list:
        task_queue.put(None) # One sentinel in the task_queue per proc
        priority_queue.put(None) # One sentinel in each priority_queue

    # Keep track of how many tasks have to be performed for each target
    task_num=0
    for command in available_commands:
        if command in shared_settings:
            task_num+=1


    # --REPORTING SECTION--
    processes_running = nb_processes

    # Each host has a list of results
    result_dict = {}
    for target in targets_OK:
        result_dict[target] = []

    # If all processes have stopped, all the work is done
    while processes_running:
        result = result_queue.get()

        if result is None: # Getting None means that one process was done
            processes_running -= 1

        else: # Getting an actual result
            (target, command, plugin_result) = result
            result_dict[target].append((command, plugin_result))

            if len(result_dict[target]) == task_num: # Done with this target
                # Print the results and update the xml doc
                output.results(target, result_dict[target])
                for processor in result_processors:
                    processor.process(target, result_dict[target])

        result_queue.task_done()

    # --TERMINATE--

    # Make sure all the processes had time to terminate
    task_queue.join()
    result_queue.join()
    #[process.join() for process in process_list] # Causes interpreter shutdown errors
    exec_time = time()-start_time

    # Output data if required.
    for processor in result_processors:
        processor.output_results(shared_settings, exec_time, PROJECT_VERSION, PROJECT_URL, targets_ERR)

    output.scan_complete(exec_time)
    if return_result:
        return result_dict

def web_start(target_list, shared_settings):
    start_time = time()
    sslyze_plugins = PluginsFinder()
    available_plugins = sslyze_plugins.get_plugins()
    available_commands = sslyze_plugins.get_commands()
    return main(start_time, NoOutput(), target_list, shared_settings, sslyze_plugins, available_plugins, available_commands, return_result=True)

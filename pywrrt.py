#!/opt/pywrrt/env/bin/python3
"""
Python Watch, Restore and Remote Transfer (pyWRRT)

Python script to monitor a directory for specified archive files and
restore said archive(s) before sending the restored files to a specified remote destination.
Wrapper for rsync and tar.

Python Version: 3.6
OS Environment: Linux; tested on CentOS Linux release 7.5.1804 (Core)
Package Requirements: rsync, tar, yum-utils, systemd-devel
"""
import shlex
import subprocess
import re
import os.path
import shutil
import platform
import threading
import sys
import logging
import time
import configparser
import argparse
import inotify.adapters
import systemd.journal

__author__ = "Simon Peter Green"
__copyright__ = "Copyright (c) 2018 Simon Peter Green"
__license__ = "MIT"
__version__ = "0.2"
__maintainer__ = "Simon Peter Green"
__email__ = "simonpetergreen@singaren.net.sg"
__status__ = "Development"

def execute_subprocess(external_command):
    """
    Wrapper to execute all external processes
    :param external_command: External command to execute
    :return:
    """
    logger = logging.getLogger(__file__)
    try:
        logger.info('Executing $ %s', external_command)
        subprocess_output = subprocess.check_output(shlex.split(external_command), stderr=subprocess.STDOUT)
    #except subprocess.CalledProcessError as error:
        #print(error.output.decode('utf-8'))
    except FileNotFoundError:
        logger.error('Command does not exist within the system!')
    return subprocess_output.decode('utf-8')


def restore_tar_archive(archived_file_fp, restore_directory_fp, additional_args=''):
    """
    Restores a tar archive into a folder and removes said archive.
    :param archived_file_fp:
    :param restore_directory_fp:
    :param additional_args:
    :return:
    """
    logger = logging.getLogger(__file__)
    try:
        os.mkdir(restore_directory_fp)
        logger.info('Created restoration directory %s', restore_directory_fp)
    except FileExistsError:
        logger.warning('Directory %s already exists', restore_directory_fp)
    restore_command = 'tar -xvf {additional_args} ' \
                      '{archived_file} -C {restore_directory}'.format(archived_file=archived_file_fp,
                                                                      restore_directory=restore_directory_fp,
                                                                      additional_args=additional_args)
    restore_output = execute_subprocess(restore_command)
    logger.debug('Restore tar output: %s', restore_output.split())
    logger.info('Restored %s into %s', archived_file_fp, restore_directory_fp)

    os.remove(archived_file_fp)
    logger.info('Removed archive %s', archived_file_fp)
    return


def recursive_rsync_to_destination(source_fp, destination_server, destination_fp, additional_args=''):
    """
    Spawns external rsync process to send a folder recursively to a directory on the remove server
    :param source_fp: Absolute file path of folder to be sent to the remote destination
    :param destination_server: Destination server details e.g. bob@remotehost
    :param destination_fp: Absolute file path of the destination folder within the remote server
    :param additional_args: additional rsync argument string
    :return:
    """
    rsync_command = 'rsync -avzr {additional_args} ' \
                    '{source_folder} ' \
                    '{destination_server}:{destination_folder}'.format(source_folder=source_fp,
                                                                       destination_server=destination_server,
                                                                       destination_folder=destination_fp,
                                                                       additional_args=additional_args)
    return execute_subprocess(rsync_command)


def archived_file_to_remote_destination(archived_fp, destination_rsync_server, destination_fp, lock):
    """
    Performs archive restore to a folder, deletion of said restore, rsync transfer of restored archive
    folder to destination rsync enabled server and performs clean-up of folder once rsync transfer has completed
    :param archived_fp:
    :param destination_rsync_server:
    :param destination_fp: Destination full file path of the remote rsync server
    :param lock: Threading lock
    :return:
    """
    lock.acquire()
    logger = logging.getLogger(__file__)
    logger.debug('Acquired threading lock')
    logger.info('Preparing to restore %s before sending to %s:%s', archived_fp, destination_rsync_server, destination_fp)

    thread_pid = str(os.getpid())
    restore_folder = ''.join([archived_fp, thread_pid, '/'])
    logger.info('Initialised restoration folder %s', restore_folder)

    try:
        start_time = time.time()
        restore_tar_archive(archived_fp, restore_folder)

        rsync_output = recursive_rsync_to_destination(restore_folder, destination_rsync_server, destination_fp)
        logger.debug('Rsync output: %s', rsync_output.split())
        logger.info('Transferred contents of %s to %s:%s', restore_folder, destination_rsync_server, destination_fp)

        shutil.rmtree(restore_folder)
        end_time = time.time()
        logger.info('Cleaned %s as transfer has completed', restore_folder)
        logger.info('Restore and transfer duration: %ds', end_time - start_time)
    finally:
        lock.release()
        logger.debug('Released threading lock')
    return


def main(config_file_path):
    logger = logging.getLogger(__file__)
    logger.setLevel(logging.DEBUG)
    journald_handler = systemd.journal.JournaldLogHandler()
    journald_handler.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
    logger_formatter = logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s %(message)s',
                                         datefmt='%Y-%m-%d %H:%M:%S')
    logger.addHandler(journald_handler)

    config = configparser.ConfigParser()
    try:
        config.read_file(open(config_file_path))
    except FileNotFoundError:
        logger.critical('Configuration file %s does not exist! Exiting...', config_file_path)
        sys.exit(1)

    log_file = config['Log']['file_path']
    file_log_handler = logging.FileHandler(filename=log_file)
    file_log_handler.setLevel(logging.DEBUG)
    file_log_handler.setFormatter(logger_formatter)
    logger.addHandler(file_log_handler)


    watched_directory = config['Watched']['directory']
    file_name_regex = config['Watched']['file_name_regex']
    remote_server = config['Destination']['server']
    remote_directory = config['Destination']['directory']

    logger.info('Started watcher')
    inotify_listener = inotify.adapters.Inotify()
    inotify_listener.add_watch(watched_directory)
    logger.info('Watching %s directory for inotify changes', watched_directory)

    threading_lock = threading.Lock()

    for event in inotify_listener.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        if 'IN_CLOSE_WRITE' not in type_names:

            continue
        if not re.search(file_name_regex, filename):
            continue

        archived_file_full_fp = os.path.join(path, filename)
        logger.debug('%s triggered by %s ', type_names, archived_file_full_fp)
        thread = threading.Thread(target=archived_file_to_remote_destination,
                                  args=(archived_file_full_fp,
                                        remote_server,
                                        remote_directory,
                                        threading_lock,))
        logger.debug('Thread setup to restore %s and transfer it to %s:%s', archived_file_full_fp,
                     remote_server, remote_directory)
        thread.daemon = True
        logger.debug('Thread starting')
        thread.start()


if __name__ == '__main__':
    if platform.system() == "Linux":
        try:
            parser = argparse.ArgumentParser()
            parser.add_argument('-C', '--config-file', help='Configuration file in INI format.', required=True)
            args = parser.parse_args()
            main(config_file_path=args.config_file)
        except KeyboardInterrupt:
            print('\nExiting on user request', file=sys.stderr)
            sys.exit(0)



#!/usr/bin/env python

"""
<Program Name>
  conformance_tester.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 26, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a tool for conformance testing with the specification.  The tool's
  behavior is governed by the design requisites defined in TAP 7 (Conformance
  testing), available at https://github.com/theupdateframework/taps.  This tool
  executes a tuf-compliant program, which is specified in .tuf-tester.yml, to
  perform compliance testing.

  This tool launches an HTTP server that listens for requests for metadata and
  targets.  It initially generates a root.json, according to the restrictions
  set in .tuf-tester.yml, and stores it in the metadata directory of the
  tuf-compliant program.  The tuf-compliant program is expected to make an
  update and save metadata and target requests to specified directories.  This
  tool runs a series of tests that validate the downloaded metadata, targets,
  and return codes of the program.  If all tests pass, this tool
  exits with a return code of SUCCESS (O).  If any of the tests fail, this tool
  exits with a return code of FAILURE (1) (optionally, it prints/logs a list of
  tests that the program failed to satisfy, or updater attacks it failed to
  block).

<Usage>
  $ python compliance_tester.py --config /tmp/.tuf-tester.yml --verbose 3

<Options>
  --config:
    Configuration file that includes the tuf-compliant program to run and
    restrictions of the repository.  For example, the tuf-compliant program may
    only support ECDSA keys, so the 'keytype' entry of the configuration file
    is set to 'ecdsa'.  The configuration file must be named '.tuf-tester.yml'
    and be a valid YML file.

  --verbose:
    Set the verbosity level of logging messages.  Accepts values 1-5.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import optparse
import logging
import os

#TODO: import statements for repository writing
import shutil
import datetime
import tempfile
import subprocess

import tuf
import tuf.client.updater
import tuf.settings
import tuf.log

import yaml
import securesystemslib

from tuf.repository_tool import *

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.conformance_tester')


def run_conformance_testing(config_file):
  """
  <Purpose>

  <Arguments>
    config_file:
      The path of the configuration file, which must be named '.tuf-tester.yml'.

 <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    None.
  """

  with open(config_file, 'r') as file_object:
    configuration = yaml.load(file_object.read())

  print('configuration: ' + repr(configuration))

  # (1) Create TUF repository
  # (2) Copy root.json to the updater's metadata store
  # (3) Test for normal update
  # (4) Test for update under attacks:
  # arbitrary installation, endless data, extraneous dependencies,
  # fast-forward, indefinite freeze, malicious mirrors, mix-and-match,
  # rollback, slow retrieval, and key compromise attacks

  command = configuration['command']
  print('command: ' + repr(command))

  """
  metadata_directory = configuration['metadata']
  targets_directory = configuration['targets']
  """

  server_process = None
  client_process = None

  try:
    pass
    server_process = subprocess.Popen(["slow_retrieval_server.py", "8001", "mode_1"])
    #client_process = subprocess.Popen([command])

  except:
    pass

  finally:
    if server_process is None:
      server_process.kill()

    """
    if client_process is None:
      client_process.kill()
    """

def create_repository():
  """

  """

  """
  #temp_directory = tempfile.mkdtemp(
  root_key_file = 'keystore/root_key'
  targets_key_file = 'keystore/targets_key'
  snapshot_key_file = 'keystore/snapshot_key'
  timestamp_key_file = 'keystore/timestamp_key'
  delegation_key_file = 'keystore/delegation_key'


  repository = create_new_repository('repository')

  # TODO: The following key types and number of keys are currently fixed, but
  # they should depend on the restrictions set in the configuration file.
  # Generate keys for the top-level roles. One key is generated for two
  # deletated roles.
  generate_and_write_rsa_keypair(root_key_file, password='password')
  generate_and_write_ed25519_keypair(targets_key_file, password='password')
  generate_and_write_ed25519_keypair(snapshot_key_file, password='password')
  generate_and_write_ed25519_keypair(timestamp_key_file, password='password')
  generate_and_write_ed25519_keypair(delegation_key_file, password='password')

  root_public = import_rsa_publickey_from_file(root_key_file + '.pub')
  targets_public = import_ed25519_publickey_from_file(targets_key_file + '.pub')
  snapshot_public = import_ed25519_publickey_from_file(snapshot_key_file + '.pub')
  timestamp_public = import_ed25519_publickey_from_file(timestamp_key_file + '.pub')
  delegation_public = import_ed25519_publickey_from_file(delegation_key_file + '.pub')

  root_private = import_rsa_privatekey_from_file(root_key_file, 'password')
  targets_private = import_ed25519_privatekey_from_file(targets_key_file, 'password')
  snapshot_private = import_ed25519_privatekey_from_file(snapshot_key_file, 'password')
  timestamp_private = import_ed25519_privatekey_from_file(timestamp_key_file, 'password')
  delegation_private = import_ed25519_privatekey_from_file(delegation_key_file, 'password')

  repository.root.add_verification_key(root_public)
  repository.targets.add_verification_key(targets_public)
  repository.snapshot.add_verification_key(snapshot_public)
  repository.timestamp.add_verification_key(timestamp_public)

  repository.root.load_signing_key(root_private)
  repository.targets.load_signing_key(targets_private)
  repository.snapshot.load_signing_key(snapshot_private)
  repository.timestamp.load_signing_key(timestamp_private)

  repository.targets.delegate('role1', [delegation_public], [target3_filepath])
  repository.targets('role1').load_signing_key(delegation_private)

  repository.targets('role1').delegate('role2', [delegation_public], [])
  repository.targets('role2').load_signing_key(delegation_private)

  repository.targets.compressions = ['gz']
  repository.snapshot.compressions = ['gz']


  repository.writeall()
  staged_metadata_directory = 'repository/metadata.staged'
  metadata_directory = 'repository/metadata'

  shutil.copytree(staged_metadata_directory, metadata_directory)
  """


def parse_options():
  """
  <Purpose>
    Parse the command-line options and set the logging level as specified by
    the user through the --verbose option.

    'conformance_tester.py' expects the --config command-line option to be set
    by the user.  --verbose is optional.

    Example:
      $ python conformance_tester.py --config /tmp/.tuf-tester.yml

    If the required option is unset, a parser error is printed and the scripts
    exits.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level for TUF logging.

  <Returns>
    A options.CONFIG_FILE string.
  """

  parser = optparse.OptionParser()

  # Add the options supported by 'conformance_tester' to the option parser.
  parser.add_option('--config', dest='CONFIG_FILE', type='string',
                    help='Specify the configuration file that includes the'
                    ' tuf-compliant command to execute.')

  parser.add_option('--verbose', dest='VERBOSE', type=int, default=2,
                    help='Set the verbosity level of logging messages.'
                    '  The lower the setting, the greater the verbosity.')

  options, args = parser.parse_args()

  # Set the logging level.
  if options.VERBOSE == 5:
    tuf.log.set_log_level(logging.CRITICAL)

  elif options.VERBOSE == 4:
    tuf.log.set_log_level(logging.ERROR)

  elif options.VERBOSE == 3:
    tuf.log.set_log_level(logging.WARNING)

  elif options.VERBOSE == 2:
    tuf.log.set_log_level(logging.INFO)

  elif options.VERBOSE == 1:
    tuf.log.set_log_level(logging.DEBUG)

  else:
    tuf.log.set_log_level(logging.NOTSET)

  # Ensure the --config command-line option is set by the user.
  if options.CONFIG_FILE is None:
    parser.error('"--config" must be set on the command-line.')

  # Return the path of the configuration file.
  return options.CONFIG_FILE



if __name__ == '__main__':

  # Parse the options and set the logging level.
  configuration_file = parse_options()

  # Return codes for conformance_tester.py.
  SUCCESS = 0
  FAILURE = 1

  # Execute the tests..


  try:
    run_conformance_testing(configuration_file)

  except (tuf.exceptions.Error) as exception:
    sys.exit(FAILURE)

  # Successfully updated the target file.
  sys.exit(SUCCESS)
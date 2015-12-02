#!/usr/bin/env python
'''
Verbose NFS connectivity nagios check

NFS timeout checks using /proc/self/mountstats from a remote host, returns the
correct nagios exit value for alert level, informational alert explains the
stats experiencing issues, GETATTR/LOOKUP/ACCESS normally indicate an issue 
connecting to the NFS share

USAGE:
	check_nfs_verbose.py <hostname> <username>

Exit Values:
	OK: 0
	WARNING: 1
	CRITICAL: 2

AUTHOR:
	Stephen McGregor (01/12/2015) (Griffith University - SMS)

Python 2.4.3 compatible :(
'''
import hashlib
import os
import re
import subprocess
import sys
import tempfile


# -- Utils ---------------------------------------------------------------------

def history_path(hostname):
	return os.path.join(tempfile.gettempdir(), '.nfs__' + hostname)


def check_output(*popenargs, **kwargs):
	'''Used to patch subprocess if we're on an old python version'''
	if 'stdout' in kwargs:
		raise ValueError('stdout argument not allowed, it will be overridden.')
	process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
	output, unused_err = process.communicate()
	retcode = process.poll()
	if retcode:
		cmd = kwargs.get("args")
		if cmd is None:
			cmd = popenargs[0]
		raise SystemError('''Process returned %s running "%s" with output %s''' % (retcode, cmd, output))
	return output

if not 'check_output' in dir(subprocess):
	subprocess.check_output = check_output


# -- Stats container -----------------------------------------------------------

class OpStat(object):
	'''Operation statistic with named attributes from /proc/self/mountstats

	This class is used to provide meaningful names for the text based input of
	the mountstats file, in this particular script all we care about is the
	major_timeouts attribute

	Attributes:
		operations (int): How many requests we've done for this operation.

		transmissions (int): How many times we've actually transmitted a RPC 
			request for this operation. As you might have gathered from the last
			entry, this can exceed the operation count due to timeouts and 
			retries.

		major_timeouts (int): How many times a request has had a major timeout. 
			Major timeouts produce 'nfs: server X not responding, still trying' 
			messages. You can have timeouts and retries without having major 
			timeouts

		bytes_sent (int): This includes not just the RPC payload but also the 
			RPC headers and so on. It closely matches the on-the-wire size.

		bytes_received (int): As with bytes sent, this is the full size.

		cumulative_queue_time (int): How long (in milliseconds) all requests 
			spent queued for transmission before they were sent.

		cumulative_response_time (int): How long (in milliseconds) it took to 
			get a reply back after the request was transmitted. The kernel 
			comments call this the RPC RTT.

		cumulative_total_request_time (int): How long (in milliseconds) all 
			requests took from when they were initially	queued to when they were 
			completely handled. The kernel calls this the RPC execution time.
	'''

	__slots__ = [
		'operations', 'transmissions', 'major_timeouts', 'bytes_sent', 
		'bytes_received', 'cumulative_queue_time', 'cumulative_response_time', 
		'cumulative_total_request_time'
	]

	def __init__(self, args):
		(self.operations, self.transmissions, self.major_timeouts, 
		self.bytes_sent, self.bytes_received, self.cumulative_queue_time, 
		self.cumulative_response_time, self.cumulative_total_request_time) = map(int, args)

	def __getstate__(self):
		return self.__slots__


class Mountstats(object):
	'''Mountstats op statistics

	Provides named attributes for the parses /proc/self/mountstats when we refer
	to it during out comparisons
	'''
	__slots__ = [
		'id', 'device', 'mountpoint',

		'NULL', 'GETATTR', 'SETATTR', 'LOOKUP', 'ACCESS', 'READLINK', 
		'READ', 'WRITE', 'CREATE', 'MKDIR', 'SYMLINK', 'MKNOD', 'REMOVE', 
		'RMDIR', 'RENAME', 'LINK', 'READDIR', 'READDIRPLUS', 'FSSTAT', 
		'FSINFO', 'PATHCONF', 'COMMIT'
	]

	def __init__(self, device, mountpoint):
		self.id = hashlib.sha1(device + mountpoint).hexdigest()
		self.device = device
		self.mountpoint = mountpoint

	def __getstate__(self):
		return self.__slots__


# -- Main ----------------------------------------------------------------------

def fetch_mountstats(hostname, username):
	'''Fetch the mountstats file from a remote host

	Presumes ssh keys have been swapped with the target host, for our purposes
	we can safely presume nagios has access. Elevated permissions are not
	required on the remote host for read access to mountstats
	'''
	try:
		return subprocess.check_output(
			['ssh', username + "@" + hostname, 'cat /proc/self/mountstats'], 
			stderr=open(os.devnull, 'w')
		)
	except:
		raise SystemError("Failed to fetch mountstats from remote host")


def persist_mountstats(hostname, stats):
	'''Read our stats from the file location

	Note:
		We cannot make use of with() until our primary monitoring environment 
		is no longer python 2.4. Review this once we update
	'''
	ouf = open(history_path(hostname), 'w+')
	ouf.write(stats)
	ouf.close()


def load_mountstats(hostname):
	'''Persist our stats to the file location

	Note:
		We cannot make use of with() until our primary monitoring environment 
		is no longer python 2.4. Review this once we update
	'''
	inf = open(history_path(hostname), 'r+')
	return inf.read()


def parse_mountstats(stats):
	'''Parse stats intp a usable form. Takes input from /proc/self/mountstats

	Iterate the text file we get, pulling information out via the compiled regex
	strings matching device information and per-op statistics
	'''
	rules = (
		('device', re.compile('^device (.+?) mounted on (.+?) with fstype (\w+)')),
		('stat', re.compile('^\t\s*([A-Z]+): (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)')),
	)

	current_device = None

	for line in stats.splitlines():
		for tok, rule in rules:
			potential_match = rule.match(line)
			if potential_match:
				if tok == 'device':
					# Throw our existing device if we aren't just starting
					if not current_device is None:
						yield (current_device.id, current_device)

					# Expand out the regex groups into variables
					_device, _mount, _type = potential_match.groups()

					# We only care about NFS, pass on all others
					if not _type == "nfs":
						continue

					current_device = Mountstats(_device, _mount)

				elif tok == 'stat':
					# split out stats and set the attribute on our mountstat
					# {ref} NULL: 0 0 0 0 0 0 0 0
					optype = potential_match.groups()[0]
					setattr(current_device, optype, OpStat(potential_match.groups()[1:]))

	# Throw the remaining device once we're done iterating
	if not current_device is None:
		yield (current_device.id, current_device)


def diff_stats(old_ms, new_ms):
	'''Diff each op-stat between our new mountstats and historical version
	Alert if we have any major_timeouts

	The only ops we really care about are:
	- Mountstats.GETATTR.major_timeouts
	- Mountstats.ACCESS.major_timeouts
	'''
	for attr in [x for x in new_ms.__slots__ if x.isupper()]:
		if getattr(new_ms, attr).major_timeouts > getattr(old_ms, attr).major_timeouts:
			yield "%s [%d]" % (attr, getattr(new_ms, attr).major_timeouts - getattr(old_ms, attr).major_timeouts)


def main(hostname, username):
	'''Fetch our new stats from the remote host ( via ssh subprocess )

	Each stat is compared to the last time we ran a check, in the event we have
	an increase in major_timeouts for any op we throw that back at nagios with
	an error exit code
	'''
	try:
		r_new_stats = fetch_mountstats(hostname, username)
	except SystemError:
		print "WARNING - Failed to fetch remote mountstats"
		sys.exit(1)

	try:
		r_old_stats = load_mountstats(hostname)
	except IOError:
		persist_mountstats(hostname, r_new_stats)
		print "Historical stats file created"
		sys.exit(0)
	
	old_stats = dict(parse_mountstats(r_old_stats))
	new_stats = dict(parse_mountstats(r_new_stats))

	persist_mountstats(hostname, r_new_stats)

	exit_code = 0

	for uid, mount in new_stats.items():
		errs = list(diff_stats(old_stats[uid], mount))
		if errs:
			print "CRITICAL - NFS Operation Errors for %s: %s" % (mount.device, ','.join(errs))
			exit_code = 2
	
	if not exit_code:
		print "OK - No NFS errors found"
	
	sys.exit(exit_code)

if __name__ == '__main__':
	# Display our help menu
	if '-h' in sys.argv:
		print sys.argv[0] + " <hostname> <username>"
		sys.exit(0)

	main(*sys.argv[1:3])






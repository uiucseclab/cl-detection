from parser import *
  
import fnmatch
import os

'''
Examines all sandbox runs by processing all of 
the .xml files in the folder 'sandbox_runs'
'''
for root, dirnames, filenames in os.walk('sandbox_runs'):
	# find all xml files
	for filename in fnmatch.filter(filenames, '*.xml'):
		filepath = os.path.join(root,filename)
		print("Processing " + filepath)			# print filename
		parse_sandbox(ET.parse(os.path.join(root,filename)))		# process file

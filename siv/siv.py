###
 ## System Integrity Verifier (SIV) - Python Application
 ##
 ## @category   Python_Application
 ## @package    system-integrity-verifier
 ## @author     Suman Barua
 ## @developer  Suman Barua <sumanbarua576@gmail.com>
 ####

 
 #!/usr/bin/env python3
from grp import getgrgid
from pprint import pprint
from datetime import datetime
import argparse, sys, json, textwrap, os, pwd, hashlib


################################## Necessary Functions Implementation ##################################
# Get details information of all the directories and subdirectories
def getDetailedDirectoryInfo(dirpath, directories, parsedArguments, report, jsonDecodedContent):
    numberOfWarnings = 0
    numberOfParsedDirectories = 0
    for directory in directories:
        numberOfParsedDirectories += 1
        fullDirPath = os.path.abspath(os.path.join(dirpath, directory))

        # Encapsulate all the directory details
        detailInfoDir[fullDirPath] = {
            "size" : os.stat(fullDirPath).st_size,
            "user" : pwd.getpwuid(os.stat(fullDirPath).st_uid).pw_name,
            "group" : getgrgid(os.stat(fullDirPath).st_gid).gr_name,
            "modified" : datetime.fromtimestamp(os.stat(fullDirPath).st_mtime).strftime('%c'),
            "access" : oct(os.stat(fullDirPath).st_mode & 0o777)
        }

        if parsedArguments.verification:
            # Write warning messages into the report file
            numberOfWarnings += writeWarningsIntoReportFile(
                report,
                detailInfoDir[fullDirPath],
                jsonDecodedContent[0],
                fullDirPath,
                "directory",
                False
            )

    # Encapsulate data count
    detailInfoDir['warning_count'] = numberOfWarnings
    detailInfoDir['dir_count'] = numberOfParsedDirectories
    return detailInfoDir


# Get details information of all the files
def getDetailedFileInfo(dirpath, filenames, parsedArguments, report, jsonDecodedContent):
    numberOfWarnings = 0
    numberOfParsedFiles = 0
    for filename in filenames:
        numberOfParsedFiles += 1
        fullFilePath = os.path.abspath(os.path.join(dirpath, filename))

        # Compute message digest using hash function
        hashFunction = parsedArguments.hash_function
        if parsedArguments.verification:
            hashFunction = jsonDecodedContent[2]['hash_type']

        # Get message digest
        message = computeMessageDigestWithHashFunction(hashFunction, fullFilePath)

        # Encapsulate all the file details
        detailInfoFile[fullFilePath] = {
            "size" : os.stat(fullFilePath).st_size,
            "user" : pwd.getpwuid(os.stat(fullFilePath).st_uid).pw_name,
            "group" : getgrgid(os.stat(fullFilePath).st_gid).gr_name,
            "modified" : datetime.fromtimestamp(os.stat(fullFilePath).st_mtime).strftime('%c'),
            "access" : oct(os.stat(fullFilePath).st_mode & 0o777),
            "hash" : message
        }

        if parsedArguments.verification:
            # Write warning messages into the report file
            numberOfWarnings += writeWarningsIntoReportFile(
                report,
                detailInfoFile[fullFilePath],
                jsonDecodedContent[1],
                fullFilePath,
                "file",
                message
            )

    # Encapsulate data count
    detailInfoFile['warning_count'] = numberOfWarnings
    detailInfoFile['file_count'] = numberOfParsedFiles
    return detailInfoFile


# Write warning messages into the report file
def writeWarningsIntoReportFile(report, detailInfo, jsonDecodedContent, fullPath, type, message):
    numberOfWarnings = 0
    if fullPath in jsonDecodedContent:
        if detailInfo['size'] != jsonDecodedContent[fullPath]['size']:
            report.write("\nWarning: {0} {1} has different size!\n".format(type, fullPath))
            numberOfWarnings += 1
        if detailInfo['user'] != jsonDecodedContent[fullPath]['user']:
            report.write("\nWarning: {0} {1} has different user!\n".format(type, fullPath))
            numberOfWarnings += 1
        if detailInfo['group'] != jsonDecodedContent[fullPath]['group']:
            report.write("\nWarning: {0} {1} has different group!\n".format(type, fullPath))
            numberOfWarnings += 1
        if detailInfo['modified'] != jsonDecodedContent[fullPath]['modified']:
            report.write("\nWarning: {0} {1} has different modification date!\n".format(type, fullPath))
            numberOfWarnings += 1
        if detailInfo['access'] != jsonDecodedContent[fullPath]['access']:
            report.write("\nWarning: {0} {1} has modified access rights!\n".format(type, fullPath))
            numberOfWarnings += 1
        if message and message != jsonDecodedContent[fullPath]['hash']:
            report.write("\nWarning: {0} {1} different message digest!\n".format(type, fullPath))
            numberOfWarnings += 1

    # Directory/File has been added
    elif fullPath not in jsonDecodedContent:
        report.write("\nWarning: {0} {1} has been added!\n".format(type, fullPath))
        numberOfWarnings += 1

    # Return total warning count
    return numberOfWarnings


# Compute message digest using hash funciton
def computeMessageDigestWithHashFunction(hashFunction, fullFilePath):
    # Compute message digest using MD-5
    hashLibrary = hashlib.sha1()
    if hashFunction == "md5":
        hashLibrary = hashlib.md5()

    # Start digesting message
    with open(fullFilePath, 'rb') as hashFile:
        content = hashFile.read()
        hashLibrary.update(content)
        message = hashLibrary.hexdigest()

    # Return message digest
    return message


# Setup necessary arguments and helper manual
def argumentAndHelperManualConfiguration():
    argumentParser = argparse.ArgumentParser(
        formatter_class = argparse.RawTextHelpFormatter,
        description = textwrap.dedent("####################### System-Integrity-Verifier (SIV) #######################"),
        epilog = "############################## Example Commands ##############################\n\n" +
                 "Initialization : {0} -i -D /etc/ -V verification.json -R report.txt -H md5\n".format(sys.argv[0]) +
                 "Verification   : {0} -v -D /etc/ -V verification.json -R report.txt\n".format(sys.argv[0]) +
                 "SIV Manual     : {0} -h".format(sys.argv[0])
    )
    argumentGroup = argumentParser.add_mutually_exclusive_group(required=True)
    argumentGroup.add_argument("-i", "--initialization", action="store_true", dest="initialization", help="Initialization mode")
    argumentGroup.add_argument("-v", "--verification", action="store_true", dest="verification", help="Verification mode")
    argumentParser.add_argument("-D", "--monitored_directory", required=True, type=str, dest="monitored_directory", help="Provide a directory for monitoring integrity")
    argumentParser.add_argument("-V", "--verification_file", required=True, type=str, dest="verification_file", help="Provide a verification file for storing records of each directory and file of the monitored directory")
    argumentParser.add_argument("-R", "--report_file", type=str, required=True, dest="report_file", help="Provide a report file for saving final report along with warnings")
    argumentParser.add_argument("-H", "--hash_function", type=str, dest="hash_function", help="Hash algorithm supported: 'sha1' and 'md5'")

    return argumentParser.parse_args()

# Write into the verification and report file
def writeIntoVerificationAndReportFile(parsedArguments, numberOfParsedDirectories, numberOfParsedFiles, startTime, jsonEncodedContent, numberOfWarnings):
    if parsedArguments.initialization:
        openMode = "w";
        headerText = "Initialization Mode Started"
        footerText = "Initialization Mode Ended"

        # Write into the verification file
        print("\nVerification file has been created at the location: {0}\n".format(os.path.abspath(parsedArguments.verification_file)))
        with open(parsedArguments.verification_file, "w") as verification:
            verification.write(jsonEncodedContent)
    else:
        openMode = "a";
        headerText = "Verification Mode Started"
        footerText = "Verification Mode Ended"

    # Write report details
    endTime = datetime.utcnow()
    with open(parsedArguments.report_file, openMode) as report:
        report.write("\n############################## {0} ##############################\n\n".format(headerText))
        report.write("Monitored directory         : {0}\n".format(os.path.abspath(parsedArguments.monitored_directory)))
        report.write("Verification file           : {0}\n".format(os.path.abspath(parsedArguments.verification_file)))
        if parsedArguments.verification:
            report.write("Report file                 : {0}\n".format(os.path.abspath(parsedArguments.report_file)))
        report.write("Total number of directories : {0}\n".format(numberOfParsedDirectories))
        report.write("Total number of files       : {0}\n".format(numberOfParsedFiles))
        if parsedArguments.verification:
            report.write("Total warnings              : {0}\n".format(numberOfWarnings))
        report.write("Total elapsed time          : {0} seconds\n".format((endTime-startTime).total_seconds()))
        report.write("\n################################ {0} ################################\n\n".format(footerText))

    print("Report file has been created at the location: {0}".format(os.path.abspath(parsedArguments.report_file)))


# Print to the stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# Ask users for their choise
def doYouWant(message):
    choice = input(message + " [y/n]: ")
    if choice.lower() == "y":
        return True
    elif choice.lower() == "n":
        return False

    # Repeat if invalid choice given
    return doYouWant(message)


# Data and system validation
def getDataAndSystemValidation(parsedArguments):
    # Check monitored directory exitst or not
    if not os.path.exists(parsedArguments.monitored_directory):
        eprint("Error: monitored directory '{0}' does not exist!\n".format(parsedArguments.monitored_directory))
        sys.exit()

    # Check monitored directory is a valid directory or not
    if not os.path.isdir(parsedArguments.monitored_directory):
        eprint("Error: monitored directory '{0}' is not a directory!\n".format(parsedArguments.monitored_directory))
        sys.exit()

    if parsedArguments.initialization:
        # Check hashing argument is specified or not
        if not parsedArguments.hash_function:
            eprint("Error: no hashing algorithm is specified! Please use option '-H'.\n")
            sys.exit()

        # Check correct hashing function is given or not
        if parsedArguments.hash_function not in ("sha1", "md5"):
            eprint("Error: wrong hashing algorithm is specified! Please use 'sha1' or 'md5'.\n")
            sys.exit()

    # Check verification file outside of monitored directory or not
    if os.path.commonprefix([parsedArguments.monitored_directory, parsedArguments.verification_file]) is parsedArguments.monitored_directory:
        eprint("Error: verification file ({0}) should be outside of monitored directory ({1})!\n".format(parsedArguments.verification_file, parsedArguments.monitored_directory))
        sys.exit()

    # Check report file outside of monitored directory or not
    if os.path.commonprefix([parsedArguments.monitored_directory, parsedArguments.report_file]) is parsedArguments.monitored_directory:
        eprint("Error: report file ({0}) should be outside of monitored directory ({1})!\n".format(parsedArguments.report_file, parsedArguments.monitored_directory))
        sys.exit()

    if parsedArguments.initialization:
        # Check verification file exists or not, if not create one (for initialization mode)
        if os.path.isfile(parsedArguments.verification_file):
            eprint("Error: verification file '{0}' already exists!\n".format(parsedArguments.verification_file))
            if not doYouWant("Overwrite existing verification file?"):
                sys.exit()
        else:
            os.open(parsedArguments.verification_file, os.O_CREAT, mode=0o777)
    else:
        # Check verification file exists or not
        if not os.path.isfile(parsedArguments.verification_file):
            eprint("Error: verification file '{0}' does not exist!\n".format(parsedArguments.verification_file))
            sys.exit()

    # Check report file exists or not, if not create one
    if os.path.isfile(parsedArguments.report_file):
        eprint("\nError: report file '{0}' already exists!\n".format(parsedArguments.report_file))
        if not doYouWant("Overwrite existing report file?"):
            sys.exit()
    else:
        os.open(parsedArguments.report_file, os.O_CREAT, mode=0o777)


################################## Program Execution Starts Here ##################################
# Setup necessary arguments and helper manual
parsedArguments = argumentAndHelperManualConfiguration()

# Initialization mode starts here
if parsedArguments.initialization:
    # Initialization mode
    startTime = datetime.utcnow()
    print("\n######################## Initialization Mode Started ########################\n")

    # Initializing variables
    detailInfo = []
    detailInfoDir = {}
    detailInfoFile = {}
    detailInfoHash = {}
    numberOfParsedFiles = 0
    numberOfParsedDirectories = 0

    # Data and system validation
    getDataAndSystemValidation(parsedArguments)

    # Recursively walk through all the directories and files
    for dirpath, directories, filenames in os.walk(parsedArguments.monitored_directory):
        # Get all the details information of directories inside the monitored directory
        detailInfoDir = getDetailedDirectoryInfo(
            dirpath,
            directories,
            parsedArguments,
            False,
            False
        )
        numberOfParsedDirectories += detailInfoDir['dir_count']
        del detailInfoDir['dir_count']
        del detailInfoDir['warning_count']

        # Get all the details information of files inside the monitored directory
        detailInfoFile = getDetailedFileInfo(
            dirpath,
            filenames,
            parsedArguments,
            False,
            False
        )
        numberOfParsedFiles += detailInfoFile['file_count']
        del detailInfoFile['file_count']
        del detailInfoFile['warning_count']

    # Bind data as json format
    detailInfo.append(detailInfoDir)
    detailInfo.append(detailInfoFile)
    detailInfoHash = {"hash_type" : parsedArguments.hash_function}
    detailInfo.append(detailInfoHash)
    jsonEncodedContent = json.dumps(detailInfo, indent=2, sort_keys=True)

    # Write into the verification and report file
    writeIntoVerificationAndReportFile(
        parsedArguments,
        numberOfParsedDirectories,
        numberOfParsedFiles,
        startTime,
        jsonEncodedContent,
        False
    )

# Verification mode starts here
elif parsedArguments.verification:
    # Verification Mode
    startTime = datetime.utcnow()
    print("\n######################## Verification Mode Started ########################\n")

    # Initializing variables
    detailInfoDir = {}
    detailInfoFile = {}
    numberOfWarnings = 0
    numberOfParsedFiles = 0
    numberOfParsedDirectories = 0

    # Data and system validation
    getDataAndSystemValidation(parsedArguments)

    # Load verification file content
    with open(parsedArguments.verification_file) as verificationContent:
        jsonDecodedContent = json.load(verificationContent)

    # Parse and match the verification file records with monitored directory
    with open(parsedArguments.report_file, "a") as report:
        # Get details information of all the directories
        report.write("\n\n#################################### Verification Mode Begin ####################################\n")
        for dirpath, directories, filenames in os.walk(parsedArguments.monitored_directory):
            detailInfoDir = getDetailedDirectoryInfo(
                dirpath,
                directories,
                parsedArguments,
                report,
                jsonDecodedContent
            )
            numberOfWarnings += detailInfoDir['warning_count']
            numberOfParsedDirectories += detailInfoDir['dir_count']
            del detailInfoDir['dir_count']
            del detailInfoDir['warning_count']

        # Check if any directory is deleted or not
        for eachDirectory in jsonDecodedContent[0]:
            if not os.path.isdir(eachDirectory):
                report.write("\nWarning: directory {0} has been removed!\n".format(eachDirectory))
                numberOfWarnings += 1

        # Get details information of all the files
        for dirpath, directories, filenames in os.walk(parsedArguments.monitored_directory):
            detailInfoFile = getDetailedFileInfo(
                dirpath,
                filenames,
                parsedArguments,
                report,
                jsonDecodedContent
            )
            numberOfWarnings += detailInfoFile['warning_count']
            numberOfParsedFiles += detailInfoFile['file_count']
            del detailInfoFile['file_count']
            del detailInfoFile['warning_count']

        # Check if any file is deleted or not
        for eachFile in jsonDecodedContent[1]:
            if not os.path.isfile(eachFile):
                report.write("\nWarning: file {0} has been deleted!\n".format(eachFile))
                numberOfWarnings += 1

    # Write into the verification and report file
    writeIntoVerificationAndReportFile(
        parsedArguments,
        numberOfParsedDirectories,
        numberOfParsedFiles,
        startTime,
        False,
        numberOfWarnings
    )
################################## Program Execution Ends Here ##################################

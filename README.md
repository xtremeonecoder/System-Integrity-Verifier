# System Integrity Verifier (SIV) - Python Application

## 1 INTRODUCTION
This simple _System Integrity Verifier (SIV)_ has been developed in _Python_. It is capable of detecting any changes or modifications, removal or addition of files or directories in a _UNIX filesystem_. In short, the fundamental goal of the assignment is to learn how to secure filesystem of the _UNIX based system_ from the intruder or unknown user who are not authorized to use and modify anything in the filesystem and also to identify any kind of changes, removals or additions occurring within the specified directory tree of _UNIX based system_. _SIV application_ helps to secure the filesystem and data by providing _Integrity-Information_ inside the filesystem.

## 2 DESIGN AND IMPLEMENTATION
### 2.1 Demonstration of Six Changes
#### 2.1.1   New or removed files/directories

#### 2.1.1.1   File/Directory Added
If any _**RecursivelyWalkedRecord**_ (like - directory / file) of the monitored directory is not found in the _**VerificationFileRecord**_, then the record is assumed to be added newly.

```_if **RecursivelyWalkedRecord** not in **VerificationFileRecord**:_```
```_report.write(“Warning: File/Directory has been added!”)_```

![Check directory or file addition](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-directory-or-file-addition.jpg "Check directory or file addition")

#### 2.1.1.2   File/Directory Removed
If any _**VerificationFileRecord**_ (like - directory / file) fails to certify that it is a valid directory / file, then the record is assumed to be removed.

```_if VerificationFileRecord is not ValidRecord:_```
```report.write(“Warning: File/Directory has been removed!”)```

![Check directory removal](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-directory-removal.jpg "Check directory removal")

![Check file removal](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-file-removal.jpg "Check file removal")

#### 2.1.2   Files with a different size than recorded
If _**RecursivelyWalkedRecord**_’s _**CurrentSize**_ does not match with _**VerificationFileRecord**_’s _**SavedSize**_, then the record is assumed to be a different size than recorded before.

```if CurrentSize not equal to SavedSize:```
```report.write(“Warning: File/Directory has a different size than recorded!”)```

![Check difference in file size](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-difference-in-file-size.jpg "Check difference in file size")

#### 2.1.3   Files with a different message digest than computed before
If _**RecursivelyWalkedRecord**_’s _**CurrentMessageDigest**_ does not match with _**VerificationFileRecord**_’s _**SavedMessageDigest**_, then the record is assumed to be a different message digest than computed before.

```if CurrentMessageDigest not equal to  SavedMessageDigest:```
```report.write(“Warning: File with a different message digest!”)```
 
![Check difference in message digest](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-difference-in-message-digest.jpg "Check difference in message digest")

#### 2.1.4   Files/directories with a different user/group
If _**RecursivelyWalkedRecord**_’s _**CurrentUser/Group**_ does not match with _**VerificationFileRecord**_’s _**SavedUser/Group**_, then the record is assumed to be with a different user/group.

```if CurrentUser/Group not equal to  SavedUser/Group:```
```report.write(“Warning: Files/directories with a different user/group!”)```

![Check difference in user](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-difference-in-user.jpg "Check difference in user") 

![Check difference in group](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-difference-in-group.jpg "Check difference in group") 

#### 2.1.5   Files/directories with modified access right
If _**RecursivelyWalkedRecord**_’s _**CurrentAccessPermission**_ does not match with _**VerificationFileRecord**_’s _**SavedAccessPermission**_, then the record is assumed to be with modified access right.

```if CurrentAccessPermission not equal to  SavedAccessPermission:```
```report.write(“Warning: Files/directories with modified access right!”)```

![Check difference in access right](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-difference-in-access-right.jpg "Check difference in access right") 

#### 2.1.6   Files/directories with a different modification date
If _**RecursivelyWalkedRecord**_’s _**CurrentModificationDate**_ does not match with _**VerificationFileRecord**_’s _**SavedModificationDate**_, then the record is assumed to be with a different modification date.

```if CurrentModificationDate does not match with SavedModificationDate:```
```report.write(“Warning: Files/directories with a different modification date!”)```

![Check difference in modification date](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Check-difference-in-modification-date.jpg "Check difference in modification date")

## 2.2 Description of Algorithm
Basically, rather than using any high level algorithm, I used general logical process to develop this simple System _Integrity Verifier (SIV)_ application. I tried to keep the code as simple as possible and tried to write function/method based script, where I tried to ensure the reuse of functions/methods for the almost same purpose. I developed functions/methods for serving specific purposes.

At first, I setup all the necessary arguments for the application commands and built the helper manual for the usage of _SIV application_. Then I separated the code for two modes, i.e. _Initialization_ and _Verification_. 

![Initialization mode](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Initialization-mode.jpg "Initialization mode")

![Verification mode](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Verification-mode.jpg "Verification mode")

I developed a simple data validation method/function, _**getDataAndSystemValidation()**_, for validating all the required data validation constraints specified in the _SIV application_ manual. The validation method is responsible for validating all the data constraints for both _Initialization_ and _Verification_ modes of the application.

 ![Data and system constraints validation method](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Data-and-system-constraints-validation-method.jpg "Data and system constraints validation method")

After validating all the necessary data and constraints, I recursively walked through all the directories, subdirectories and then files of the specified monitored directory. Initially I recursively walked through all the directories and subdirectories of the specified monitored directory. For serving that purpose, I developed a comprehensive method, _**getDetailedDirectoryInfo()**_, which works for both  _Initialization_ and _Verification_ modes and returns all the details of the directories or subdirectories.

 ![Method that provides detailed information of directories and subdirectories](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Method-that-provides-detailed-information.jpg "Method that provides detailed information of directories and subdirectories")

After getting all the directory details, I recursively walked through all the files of the specified monitored directory. For serving that purpose, I developed another comprehensive method, _**getDetailedFileInfo()**_, which works for both  _Initialization_ and _Verification_ modes and returns all the details of the files in the monitored directory.

![Method that provides detailed information of files](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Method-that-provides-detailed-information-of-files.jpg "Method that provides detailed information of files")

And next, I encapsulate all the directory information and file information that got from _**getDetailedDirectoryInfo()**_ and _**getDetailedFileInfo()**_ functions successively. After encapsulating the data, I dump that _JSON_ formatted data into _JSON Object_ (only for Initialization mode).

![Dumping JSON formatted data into JSON Object](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Dumping-JSON-formatted-data-into-JSON-Object.jpg "Dumping JSON formatted data into JSON Object")

Finally write the _JSON_ formatted (directory, file and hashing function details) data into the _**verification.json**_ file and the report related queries into the _**report.txt**_ file using the method _**writeIntoVerificationAndReportFile()**_. 

![Method that writes JSON data into verification file and writes report](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/writes-JSON-data-into-verification-file.jpg "Method that writes JSON data into verification file and writes report")

I developed a separate method, _**writeWarningsIntoReportFile()**_, for writing warnings of any changes in the filesystem into the _**report.txt**_ file.

![Method that writes warnings into report file](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Method-that-writes-warnings-into-report-file.jpg "Method that writes warnings into report file")

For computing the hashing message digest, I developed a comprehensive function, _**computeMessageDigestWithHashFunction()**_, which will be reused time to time for both _Initialization_ and _Verification_ modes with separate arguments.
 
![Method that computes hashing message digest](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Method-that-computes-hashing-message-digest.jpg "Method that computes hashing message digest")

## 2.3 Verification File Format
In the verification file, I’m storing all the data as _JSON (JavaScript Object Notation)_ format. Because _JSON_ is a one of the most feasible and convenient data formats, which is very easily readable and clearly understandable by human. Alongside, it is easy to handle and manipulate _JSON_ data compare to other data format. In my verification file, I stored data in three segments. 

_In first segment, I stored all the details of the directories and subdirectories._
_In second segment, I stored all the details of the files._
_In third segment, I stored hash function information._

The key of the directory and file information is the full-path of directory and file itself as mentioned in the structure. _JSON_ file structure is given below - 

![JSON file structure](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/JSON-file-structure.jpg "JSON file structure")
 
![Verification file format](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Verification-file-format.jpg "Verification file format")

## 2.4 Verification File Datatype
In the verification file, I’m storing directory and file information of different _datatypes_. Below I showed the different _datatypes_ I used for storing information in the verification file -

![Verification File Datatype](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Verification-File-Datatype.jpg "Verification File Datatype")

## 2.5 Programming Language
I used programming language – _Python_ for developing _System Integrity Verifier (SIV)_. _Python_ is a general-purpose language and can be used to build just about anything. It is primarily used in developing solutions to complex issues within a short-time and less lines of code than many other languages. Professionally, _Python_ is great for data analysis, _Artificial Intelligence_ and _Scientific Computing_. Its simplicity, user-friendly features, intuitive coding style and easy use in _Data Science_ convinced me to use _Python_ for developing this _SIV-Application_.

## 2.6 Software Dependencies
I executed the _SIV Application_ on _**Ubuntu 18.04.1 LTS**_.

![Ubuntu Version of Host](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Ubuntu-Version-of-Host.jpg "Ubuntu Version of Host")

Usually _Python_ comes by default with the _Ubuntu_ installation. With _**Ubuntu 18.04.1 LTS**_ pack, we get _**Python 2.7.15rc1**_, but I developed this _SIV Application_ in _Python3_ environment and tested successfully in _**Python 3.6.7**_. So I would recommend you to have one of these two _**Python Versions (Python 3.6.6 or Python 3.6.7)**_ on your testing system.
 
![Python Version of Host PC](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Python-Version-of-Host-PC.jpg "Python Version of Host PC")

## 3 SIV USAGE
*siv.py [-h] (-i | -v) -D MONITORED_DIRECTORY -V VERIFICATION_FILE -R REPORT_FILE [-H HASH_FUNCTION]*

## Optional Arguments
-h, --help            show this help message and exit
-i, --initialization  Initialization mode
-v, --verification    Verification mode
-D MONITORED_DIRECTORY, --monitored_directory MONITORED_DIRECTORY
Provide a directory for monitoring integrity
-V VERIFICATION_FILE, --verification_file VERIFICATION_FILE
Provide a verification file for storing records of each directory and file of the monitored directory
-R REPORT_FILE, --report_file REPORT_FILE
Provide a report file for saving final report along with warnings
-H HASH_FUNCTION, --hash_function HASH_FUNCTION
Hash algorithm supported: 'sha1' and 'md5'

## Sample Commands
Initialization   	      : _./siv.py -i -D /etc/ -V verification.json -R_ report.txt -H md5
Verification     	      : _./siv.py -v -D /etc/ -V verification.json -R_ report.txt
SIV Help Manual           : _./siv.py -h_
 
![System Integrity Verifier (SIV) Usages](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/System-Integrity-Verifier-Usages.jpg "System Integrity Verifier (SIV) Usages")

## Most Common Operations

I executed the _SIV application_ in _Initialization_ mode using following command - 

```./siv.py -i -D '/home/suman/Documents/pythonproject/subr18' -V 'verification.json' -R 'report.txt' -H 'md5'```

![Executing SIV in Initialization Mode](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Executing-SIV-in-Initialization-Mode.jpg "Executing SIV in Initialization Mode")

After executing the _SIV application_ in _Initialization Mode_, I got _Initialization Report_ as follows – 

![SIV Initialization Report](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/SIV-Initialization-Report.jpg "SIV Initialization Report")

After executing the _SIV application_ in _Initialization Mode_, I got following directories, subdirectories and files information into the verification file - 

![Verification data after SIV Initialization](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Verification-data-after-SIV-Initialization.jpg "erification data after SIV Initialization")

Then I executed the _SIV application_ in _Verification_ mode using following command - 

```./siv.py -v -D '/home/suman/Documents/pythonproject/subr18' -V 'verification.json' -R 'report.txt'```
 
![Executing SIV in Verification Mode](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Executing-SIV-in-Verification-Mode.jpg "Executing SIV in Verification Mode")

After executing the _SIV application_ in _Verification Mode_, I got _Verification Report_ without warning message as follows –

![SIV Verification Report (without warning)](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/SIV-Verification-Report.jpg "SIV Verification Report (without warning)")

Then I changed inside monitored directory and executed the _SIV application_ in _Verification_ mode again using following command to see how are the changes warning messages coming along - 

```./siv.py -v -D '/home/suman/Documents/pythonproject/subr18' -V 'verification.json' -R 'report.txt'```
 
![Executing SIV in Verification Mode (After Modifying Filessytem)](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/Executing-SIV-in-Verification-Mode-Again.jpg "Executing SIV in Verification Mode (After Modifying Filessytem)")

After executing the _SIV application_ again in _Verification Mode_, I got _Verification Report_ with warnings message as follows –

![SIV Verification Report (with warnings)](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/SIV-Verification-Report-Again.jpg "SIV Verification Report (with warnings)")

I executed following command on terminal for _SIV_ helper manual -

```./siv.py -h```

![SIV Helper Manual](https://github.com/xtremeonecoder/system-integrity-verifier/blob/master/documentation/SIV-Helper-Manual.jpg "SIV Helper Manual")

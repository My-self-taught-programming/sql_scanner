# sql_scanner
A SQL Injection Scanner

This program is highly influenced by the the online tutorial from PythonCode.com (https://www.thepythoncode.com/article/sql-injection-vulnerability-detector-in-python)
PyhonCode has many tutorials for people within the python and cybersecurity communities. This program has been altered to look for more than just the SQL errors PythonCode  program was looking for.
The use of errors.xml from https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/errors.xml provided my program with more error messages to search for when scanning webpages.
Also the use of a while loop to continuly run the program helps with repeated scanning of webpages.

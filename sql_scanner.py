import requests
from bs4 import BeautifulSoup 
from urllib.parse import urljoin
from pprint import pprint
import pyfiglet

banner = pyfiglet.figlet_format("SQL SCANNER")

print(banner)
print("\nWith GREAT power comes GREAT responsability!\n")

# start a HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
while True:
	

	def get_all_forms(url):
	
		soup = BeautifulSoup(s.get(url).content, "html.parser")
		return soup.find_all("form")

	def get_form_details(form):
	
		details = {}

		try:
			action = form.attrs.get("action").lower()
		except:
			action = None

		method = form.attrs.get("method", "get").lower()

		inputs = []
		for input_tag in form.find_all("input"):
			input_type = input_tag.attrs.get("type", "text")
			input_name = input_tag.attrs.get("name")
			input_value = input_tag.attrs.get("value", "")
			inputs.append({"type": input_type, "name": input_name, "value":input_value})

		details["action"] = action
		details["method"] = method
		details["inputs"] = inputs
		return details

	def errors_detected(response):
		errors = {
			# MySQL
			"you have an error in this sql Syntax;",
			"warning: mysql",
			"SQL syntax.*?MySQL",
			"Warning.*?\Wmysqli?_",
			"MySQLSyntaxErrorException",
			"valid MySQL result",
			"check the manual that (corresponds to|fits) your MySQL server version",
			'''check the manual that (corresponds to|fits) your MariaDB server version fork="MariaDB" ''',
			'''check the manual that (corresponds to|fits) your Drizzle server version fork="Drizzle" ''',
			"Unknown column '[^ ]+' in 'field list'",
			"MySqlClient\.",
			"com\.mysql\.jdbc",
			"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
			"Pdo[./_\\]Mysql",
			"MySqlException",
			"SQLSTATE\[\d+\]: Syntax error or access violation",
			'''MemSQL does not support this type of query fork="MemSQL"''',
			'''is not supported by MemSQL" fork="MemSQL"''',
			'''unsupported nested scalar subselect" fork="MemSQL"''',
			 # SQl Server
			"unclosed quotation mark after the character string",
			# Oracle
			"quoted string not properly terminated",
			#PostgreSQL
			"PostgreSQL.*?ERROR",
			"Warning.*?\Wpg_",
			"valid PostgreSQL result",
			"Npgsql\.",
			"PG::SyntaxError:",
			"org\.postgresql\.util\.PSQLException",
			"ERROR:\s\ssyntax error at or near",
			"ERROR: parser: parse error at or near",
			"PostgreSQL query failed",
			"org\.postgresql\.jdbc",
			"Pdo[./_\\]Pgsql",
			"PSQLException",
			#Microsoft SQL Server
			"Driver.*? SQL[\-\_\ ]*Server",
			"OLE DB.*? SQL Server",
			"\bSQL Server[^&lt;&quot;]+Driver",
			"Warning.*?\W(mssql|sqlsrv)_",
			"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
			"System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)",
			"(?s)Exception.*?\bRoadhouse\.Cms\.",
			"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
			"\[SQL Server\]",
			"ODBC SQL Server Driver",
			"ODBC Driver \d+ for SQL Server",
			"SQLServer JDBC Driver",
			"com\.jnetdirect\.jsql",
			"macromedia\.jdbc\.sqlserver",
			"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
			"com\.microsoft\.sqlserver\.jdbc",
			"Pdo[./_\\](Mssql|SqlSrv)",
			"SQL(Srv|Server)Exception",
			"Unclosed quotation mark after the character string",
			#Microsoft Access
			"Microsoft Access (\d+ )?Driver",
			"JET Database Engine",
			"Access Database Engine",
			"ODBC Microsoft Access",
			"Syntax error \(missing operator\) in query expression",
			#Oracle
			"\bORA-\d{5}",
			"Oracle error",
			"Oracle.*?Driver",
			"Warning.*?\W(oci|ora)_",
			"quoted string not properly terminated",
			"SQL command not properly ended",
			"macromedia\.jdbc\.oracle",
			"oracle\.jdbc",
			"Zend_Db_(Adapter|Statement)_Oracle_Exception",
			"Pdo[./_\\](Oracle|OCI)",
			"OracleException",
			#IBM DB2">
			"CLI Driver.*?DB2",
			"DB2 SQL error",
			"\bdb2_\w+\(",
			"SQLCODE[=:\d, -]+SQLSTATE",
			"com\.ibm\.db2\.jcc",
			"Zend_Db_(Adapter|Statement)_Db2_Exception",
			"Pdo[./_\\]Ibm",
			"DB2Exception",
			"ibm_db_dbi\.ProgrammingError",
			#Informix">
			"Warning.*?\Wifx_",
			"Exception.*?Informix",
			"Informix ODBC Driver",
			"ODBC Informix driver",
			"com\.informix\.jdbc",
			"weblogic\.jdbc\.informix",
			"Pdo[./_\\]Informix",
			"IfxException",
			#Firebird">
			"Dynamic SQL Error",
			"Warning.*?\Wibase_",
			"org\.firebirdsql\.jdbc",
			"Pdo[./_\\]Firebird",
			#SQLite">
			"SQLite/JDBCDriver",
			"SQLite\.Exception",
			"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
			"Warning.*?\W(sqlite_|SQLite3::)",
			"\[SQLITE_ERROR\]",
			"SQLite error \d+:",
			"sqlite3.OperationalError:",
			"SQLite3::SQLException",
			"org\.sqlite\.JDBC",
			"Pdo[./_\\]Sqlite",
			"SQLiteException",
			#SAP MaxDB">
			"SQL error.*?POS([0-9]+)",
			"Warning.*?\Wmaxdb_",
			"DriverSapDB",
			"-3014.*?Invalid end of SQL statement",
			"com\.sap\.dbtech\.jdbc",
			"\[-3008\].*?: Invalid keyword or missing delimiter",
			#Sybase">
			"Warning.*?\Wsybase_",
			"Sybase message",
			"Sybase.*?Server message",
			"SybSQLException",
			"Sybase\.Data\.AseClient",
			"com\.sybase\.jdbc",
			#Ingres">
			"Warning.*?\Wingres_",
			"Ingres SQLSTATE",
			"Ingres\W.*?Driver",
			"com\.ingres\.gcf\.jdbc",
			#FrontBase">
			"Exception (condition )?\d+\. Transaction rollback",
			"com\.frontbase\.jdbc",
			"Syntax error 1. Missing",
			"(Semantic|Syntax) error [1-4]\d{2}\.",
			#HSQLDB">
			"Unexpected end of command in statement \[",
			"Unexpected token.*?in statement \[",
			"org\.hsqldb\.jdbc",
			#H2">
			"org\.h2\.jdbc",
			"\[42000-192\]",
			#MonetDB">
			"![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)",
			"\[MonetDB\]\[ODBC Driver",
			"nl\.cwi\.monetdb\.jdbc",
			#Apache Derby">
			"Syntax error: Encountered",
			"org\.apache\.derby",
			"ERROR 42X01",
			#Vertica">
			", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):",
			"/vertica/Parser/scan",
			"com\.vertica\.jdbc",
			"org\.jkiss\.dbeaver\.ext\.vertica",
			"com\.vertica\.dsi\.dataengine",
			#Mckoi">
			"com\.mckoi\.JDBCDriver",
			"com\.mckoi\.database\.jdbc",
			"&lt;REGEX_LITERAL&gt;",
			#Presto">
			"com\.facebook\.presto\.jdbc",
			"io\.prestosql\.jdbc",
			"com\.simba\.presto\.jdbc",
			"UNION query has different number of fields: \d+, \d+",
			#Altibase">
			"Altibase\.jdbc\.driver",
			#MimerSQL">
			"com\.mimer\.jdbc",
			"Syntax error,[^\n]+assumed to mean",
			#CrateDB">
			"io\.crate\.client\.jdbc",
			#Cache">
			"encountered after end of query",
			"A comparison operator is required here",
			#Raima Database Manager">
			"-10048: Syntax error",
			"rdmStmtPrepare\(.+?\) returned",
			#Virtuoso">
			"SQ074: Line \d+:",
			"SR185: Undefined procedure",
			"SQ200: No table ",
			"Virtuoso S0002 Error",
			"\[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\]",
		}

		for error in errors:
			if error in response.content.decode().lower():
				print("This is the the detected error:", error)
				return True
		return False

	def SQL_error_scan(url):
		for c in "\"'":
			new_url = f"{url}{c}"
			print("[!] Trying", new_url)
			res = s.get(new_url)
			if errors_detected(res):
				print("[+] SQl Injection vulnerability detected, link:", new_url)
			return
		forms = get_all_forms(url)
		print(f"[+] Detected {len(forms)} forms on {url}.")
		for form in forms:
			form_details = get_form_details(form)
			for c in "\"'":
				data = {}
				for input_tag in form_details["inputs"]:
					if input_tag["value"] or input_tag["type"] == "hidden":
						try:
							data[input_tag["name"]] = input_tag["value"] + c
						except:
							pass
					elif input_tag["type"] != "submit":
						data[input_tag["name"]] = f"test{c}"
				url = urljoin(url, form_details["action"])
				if form_details["method"] == "post":
					res = s.post(url, data=data)
				elif form_details["method"] == "get":
					res = s.get(url, params=data)
				if vulnerability_check(res):
					print("[+] SQL Injections vulnerability detected, link:", url)
					print("[+] Form:")
					pprint(form_details)
					break

	user_input = input("What Website would you like to Scan?:\n*quit to close program*\n")
	url = user_input
	if user_input == "quit":
		break
	SQL_error_scan(url)

# if __name__ == "__main__":
# 	url = "http://testphp.vulnweb.com/artists.php?artist=1"
# 	SQL_error_scan(url)
# pyldapsearch

This is designed to be a python "port" of the ldapsearch BOF by TrustedSec, which is a part of this [repo](https://github.com/trustedsec/CS-Situational-Awareness-BOF).

pyldapsearch allows you to execute LDAP queries from Linux in a fashion similar to that of the aforementioned BOF. Its output format closely mimics that of the BOF and all query output will automatically be logged to the user's home directory in `.pyldapsearch/logs`, which can ingested by [bofhound](https://github.com/fortalice/bofhound).

## Why would I ever use this?
Great question. pyldapsearch was built for a scenario where the operator is utilizing Linux and is attempting to issue LDAP queries while flying under the radar (BloodHound will be too loud, expensive LDAP queries are alerted on, etc). When pyldapsearch is combined with bofhound, you can still obtain BloodHound compatible data that allows for AD visualization and identification of ACL-based attack paths, which are otherwise difficult to identify through manually querying LDAP.

Outside of usage during detection-conscious and bofhound-related situations, pyldapsearch can be useful for issuing targeted, one-off LDAP queries during generic engagements.

## Installation
Use `pip3` or `pipx`
```
pip3 install pyldapsearch
```

## Usage
```
Usage: pyldapsearch [OPTIONS] TARGET FILTER

  Tool for issuing manual LDAP queries which offers bofhound compatible output

Arguments:
  TARGET  [[domain/]username[:password]  [required]
  FILTER  LDAP filter string  [required]

Options:
  -attributes TEXT       Comma separated list of attributes
  -limit INTEGER         Limit the number of results to return  [default: 0]
  -dc-ip TEXT            Domain controller IP or hostname to query
  -base-dn TEXT          Search base distinguished name to use. Default is
                         base domain level
  -no-sd                 Do not add nTSecurityDescriptor as an attribute
                         queried by default. Reduces console output
                         significantly
  -debug                 Turn DEBUG output ON
  -hashes LMHASH:NTHASH  NTLM hashes, format is LMHASH:NTHASH
  -no-pass               Don't ask for password (useful for -k)
  -k                     Use Kerberos authentication. Grabs credentials from
                         ccache file (KRB5CCNAME) based on target parameters.
                         If valid credentials cannot be found, it will use the
                         ones specified in the command line
  -aesKey TEXT           AES key to use for Kerberos Authentication (128 or
                         256 bits)
  -ldaps                 Use LDAPS instead of LDAP
  -no-smb                Do not make a SMB connection to the DC to get its
                         hostname (useful for -k). Requires a hostname to be
                         provided with -dc-ip
  -silent                Do not print query results to console (results will
                         still be logged)
  --help                 Show this message and exit.
```

## Examples
Query all the data - if you intend to do this, just run BloodHound :)
```
pyldapsearch ez.lab/administrator:pass '(objectClass=*)'
```

Query only the name, memberOf and ObjectSID of the user matt
```
pyldapsearch ez.lab/administrator:pass '(sAMAccountName=matt)' -attributes name,memberof,objectsid
```

Query all attributes for all user objects, but only return 3 results
```
pyldapsearch ez.lab/administrator:pass '(objectClass=user)' -limit 3
```

Query all attributes of the user matt, specifying the IP of the DC to query
```
pyldapsearch ez.lab/administrator:pass '(&(objectClass=user)(name=matt))' -dc-ip 10.4.2.20
```

Query all objects, specifying the search base to use
```
pyldapsearch ez.lab/administrator:pass '(objectClass=*)' -base-dn 'CN=Users,DC=EZ,DC=LAB'
```

Execute a query without displaying query results to the console (results will still be logged)
```
pyldapsearch ez.lab/administrator:pass '(objectClass=*)' -silent
```

Perform a query using an anonymous bind
```
pyldapsearch 'ez.lab'/'':'' '(objectClass=*)'
```

## Development
pyldapsearch uses Poetry to manage dependencies. Install from source and setup for development with:
```shell
git clone https://github.com/fortalice/pyldapsearch
cd pyldapsearch
poetry install
poetry run pyldapsearch
```

## References
- ldapsearch ([CS-Situational-Awareness-BOF](https://github.com/trustedsec/cs-situational-awareness-bof))
- [ldapconsole](https://github.com/p0dalirius/ldapconsole)
# This is a quick hack to convert an openldap schema file to a form which
# can be loaded into Samba4/AD.
#
# Inspired by:
# http://david-latham.blogspot.co.uk/2012/12/extending-ad-schema-on-samba4-part-2.html
# https://github.com/linuxplayground/yubikey-ldap/tree/master/samba4-schema
#
# (c) 2017 Brian Candler <b.candler@pobox.com>
# -------------------------------------------------------------------------
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
# -----------------------------------------------------------------------

from __future__ import print_function
import sys
import re
from collections import OrderedDict

BASEDN = 'dc=samba4,dc=internal'

# RFC 2252 to https://technet.microsoft.com/en-us/library/cc961740.aspx
SYNTAX_MAP = {
    '1.3.6.1.4.1.1466.115.121.1.7':  ('2.5.5.8',   1), # boolean
    '1.3.6.1.4.1.1466.115.121.1.12': ('2.5.5.1', 127), # DN
    '1.3.6.1.4.1.1466.115.121.1.15': ('2.5.5.3',  27), # DirectoryString
    '1.3.6.1.4.1.1466.115.121.1.26': ('2.5.5.5',  22), # IA5String
    '1.3.6.1.4.1.1466.115.121.1.27': ('2.5.5.9',  10), # Integer
}
obj = None
for line in sys.stdin:
    if re.match(r'^\s*(#|$)', line): continue
    m = re.match(r'^attributetype\s+\(\s+(\S+)', line)
    if m:
        obj = OrderedDict([
            ('objectClass', ['top', 'attributeSchema']),
            ('attributeID', m.group(1)),
            ('isSingleValued', 'FALSE'),
        ])
        continue
    m = re.match(r'^objectclass\s+\(\s+(\S+)', line)
    if m:
        obj = OrderedDict([
            ('objectClass', ['top', 'classSchema']),
            ('governsID', m.group(1)),
        ])
        continue
    m = re.match(r'^\s*NAME\s+[\'"](.+)[\'"]', line)
    if m:
        obj.update([
            ('cn', m.group(1)),
            ('name', m.group(1)),
            ('lDAPDisplayName', m.group(1)),
        ])
        continue
    m = re.match(r'^\s*DESC\s+[\'"](.+)[\'"]', line)
    if m:
        obj.update([
            ('description', m.group(1)),
        ])
        continue
    m = re.match(r'^\s*(EQUALITY|SUBSTR)\s+(\S+)', line)
    if m:
        # Not supported by AD?
        # https://technet.microsoft.com/en-us/library/cc961575.aspx
        continue
    m = re.match(r'^\s*SYNTAX\s+(\S+)', line)
    if m:
        obj.update([
            ('attributeSyntax', SYNTAX_MAP[m.group(1)][0]),
            ('oMSyntax', SYNTAX_MAP[m.group(1)][1]),
        ])
        continue
    if re.match(r'^\s*SINGLE-VALUE', line):
        obj.update([
            ('isSingleValued', 'TRUE'),
        ])
        continue
    if re.match(r'^\s*AUXILIARY', line):
        # https://msdn.microsoft.com/en-us/library/ms679014(v=vs.85).aspx
        # https://technet.microsoft.com/en-us/library/2008.05.schema.aspx
        obj.update([
            ('objectClassCategory', '3'),
        ])
        continue
    if re.match(r'^\s*STRUCTURAL', line):
        obj.update([
            ('objectClassCategory', '1'),
        ])
        continue
    m = re.match(r'^\s*SUP\s+(\S+)', line)
    if m:
        obj.update([
            ('subClassOf', m.group(1)),
        ])
        continue
    m = re.match(r'^\s*(MAY|MUST)\s+\((.*)\)\s*$', line)
    if m:
        attrs = m.group(2).split('$')
        obj.update([
            ('%sContain' % m.group(1).lower(), [v.strip() for v in attrs]),
        ])
        continue
    m = re.match(r'^\s*(MAY|MUST)\s+(\w+)\s*$', line)
    if m:
        obj.update([
            ('%sContain' % m.group(1).lower(), m.group(2)),
        ])
        continue
    if re.match(r'^\s*\)', line) and obj:
        print("dn: CN=%s,CN=Schema,CN=Configuration,%s" % (obj['cn'], BASEDN))
        print("changetype: add")
        for k in obj:
            if type(obj[k]) == list:
                for v in obj[k]:
                    print("%s: %s" % (k, v))
            else:
                print("%s: %s" % (k, obj[k]))
        print()
        obj = None
        continue
    print("??? %s" % line, file=sys.stderr)

#!/bin/sh
#
#  This script makes an HTML page from a simple directory listing
#
#
cat >index.html <<EOF
<html>
<title>Index of FreeRADIUS.org's RFC site</title>
<body>

<h1>Index of FreeRADIUS.org's RFC site</h1>

List of <a href="attributes.html">RADIUS attributes</A>
<p>

EOF

#
#  include the message, if any exists
#
if [ -e message ]; then
  echo "<pre>" >> index.html
  cat .message >> index.html
  echo "</pre>" >> index.html
fi

#
#  for all of the text files, do this
#
cat >>index.html <<EOF
<h2>RFC's</h2>
EOF

for x in rfc*.html;do
  y=`echo $x | sed 's/rfc//;s/\.html//'`
  echo "<a href=\"$x\">RFC $y</a>" >> index.html
  if [ -e $x.gz ]; then
    echo "<a href=\"$x.gz\">(gzipped)</a>" >> index.html
  fi
  y="attributes-rfc$y.html";
  if [ -f $y ];then
    echo "<a href=\"$y\">(attributes)</a>" >> index.html
  fi
  echo "<br />" >> index.html
done

cat >>index.html <<EOF
<h2>Other files</h2>
EOF

#
#  for all of the text files, do this
#
for x in *.txt;do
  y=`echo $x | sed ';s/\.txt/.html/'`
  if [ ! -f $y ];then
    echo "<a href=\"$x\">$x</a>" >> index.html
    if [ -e $x.gz ]; then
      echo "<a href=\"$x.gz\">(gzipped)</a>" >> index.html
    fi
    echo "<br />" >> index.html
  fi
done
echo "</body></html>" >> index.html

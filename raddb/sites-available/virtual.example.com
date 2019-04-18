#  -*- text -*-
######################################################################
#
#	Sample virtual server for internally proxied requests.
#
#	$Id$
#
######################################################################

#
#  You will want to edit this to your local needs.  We suggest copying
#  the text from the "default" file here, and then editing the text.
#  That way, any changes to the "default" file will not affect this
#  virtual server, and vice-versa.
#
#  When this virtual server receives the request, the original
#  attributes can be accessed as "outer.request", "outer.control", etc.
#  See "man unlang" for more details.
#

#
#  This example virtual server will listen on alternate ports
#  and perform basic authentication and accounting.
#  Consult the default file for information on the syntax and available options.
#

server virtual.example.com {

	#  In v4, all "server" sections MUST start with a "namespace"
	#  parameter.  This tells the server which protocol is being used.
	#  Consult the sites-available/default for more information and documentation.

	namespace = radius

	#
	#  Define our listeners and the types of application packets we expect.
	#
	listen {
		type = Access-Request

		transport = udp

		udp {
			ipaddr = *
			port = 11812
		}
	}

	#
	#  Our listener for Accounting
	#
	listen {
		type = Accounting-Request

		transport = udp

		udp {
			ipaddr = *
			port = 11813
		}
	}

	#
	#  Now we define our policy framework for how this virtual server will handle various application packets.
	#  Consult the default file for information on the syntax and available options.
	recv Access-Request {
		#  insert policies here

		#  In this example we simply validate locally

		filter_username

		auth_log

		files

		pap
	}

	send Access-Accept {
		#  insert policies here
	}

	recv Accounting-Request {
		#  insert policies here

		#
		#  Ensure that we have a semi-unique identifier for every
		#  request, and many NAS boxes are broken.
		#
		acct_unique

		#
		#  Read the 'acct_users' file
		#
		files
	}

	send Accounting-Response {

		#
		#  Create a 'detail'ed log of the packets.
		#  Note that accounting requests which are proxied
		#  are also logged in the detail file.
		#
		detail

		#
		#  Filter attributes from the accounting response.
		#
		attr_filter.accounting_response

	}

	#
	#  Allow for PAP in our example
	#
	authenticate pap {
		pap
	}

#  etc.
}

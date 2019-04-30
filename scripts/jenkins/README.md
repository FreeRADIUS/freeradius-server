### Jenkins scripted build pipeline for FreeRADIUS

#### Summary

The Jenkinsfile in this directory is used to build packages for
different Linux distributions.  They are mostly here for the
FreeRADIUS development team, and they create the packages available at
[packages.networkradius.com](https://packages.networkradius.com).

The Jenkinsfile is meant to be run with [Jenkins](https://jenkins.io/)
and uses [Docker](https://www.docker.com/) and the files in
`scripts/docker/` directory to build packages for multiple
distributions on one server.

#### Usage

To build these packages, you need the following software:
* [Docker](https://www.docker.com/)
* [Jenkins](https://jenkins.io/) with the following plugins:
 * [Pipeline](https://plugins.jenkins.io/workflow-aggregator)
 * [Docker Pipeline](https://plugins.jenkins.io/docker-workflow)

Once the software is installed, you should create a new Pipeline Item
in Jenkins and [configure the job to run the
Jenkinsfile](https://jenkins.io/pipeline/getting-started-pipelines/#loading-pipeline-scripts-from-scm)

The Jenkinsfile currently builds packages for the following platforms:

* Ubuntu 16.04 (Xenial Xerus)
* Ubuntu 18.04 (Bionic Beaver)
* Debian 9 (Stretch)
* CentOS 7 

Once complete, the packages are available as artifacts and accessible
from the job page by clicking the "Build Artifacts" link or by
accessing the url:

* https://\<jenkins\_uri\>/job/\<job\_name\>/\<build\_number\>/artifact

The packages can also be access from the last successful build on the
project page, by clicking the "Last Successful Artifacts" link, or by
going to the URL:

* https://\<jenkins\_uri\>/job/\<job\_name\>/lastSuccessfulBuild/artifact/

That page contains directories, which in turn contain packages for
each of the Linux distributions.

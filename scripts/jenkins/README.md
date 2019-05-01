### Jenkins scripted build pipeline for FreeRADIUS

#### Summary

The Jenkinsfile in this directory is used to build packages for different linux
distributions.  They are mostly here for the FreeRADIUS development team and
creates the packages available at
[packages.networkradius.com](https://packages.networkradius.com).  The
Jenkinsfile is meant to be run with [Jenkins](https://jenkins.io/) and uses
[Docker](https://www.docker.com/) and the Dockerfiles in the
distribution-specific subdirectories to be able to build packages for multiple
distributions on one server.

#### Usage

To build these packages, you need the following software:
* [Docker](https://www.docker.com/)
* [Jenkins](https://jenkins.io/) with the following plugins:
 * [Pipeline](https://plugins.jenkins.io/workflow-aggregator)
 * [Docker Pipeline](https://plugins.jenkins.io/docker-workflow)

Once you have all the necessary software installed it's just a matter of
creating a new Pipeline Item in Jenkins and [configuring the job to run the
Jenkinsfile](https://jenkins.io/pipeline/getting-started-pipelines/#loading-pipeline-scripts-from-scm) 

The Jenkinsfile currently builds packages for the following platforms:

* Ubuntu 14.04 (Trusty Tahir)
* Ubuntu 16.04 (Xenial Xerus)
* Ubuntu 18.04 (Bionic Beaver)
* Debian 8 (Jessie)
* Debian 9 (Stretch)
* Centos 6
* CentOS 7 

Once complete the packages are available as artifacts and accessible from the
job page by clicking the "Build Artifacts" link or by accessing the url
https://\<jenkins\_uri\>/job/\<job\_name\>/\<build\_number\>/artifact.  You can
also access the packages from the last successful build on the project page by
clicking the "Last Successful Artifacts" link, or by going to the URL
https://\<jenkins\_uri\>/job/\<job\_name\>/lastSuccessfulBuild/artifact/ 

On that page, there are directories containing packages for each of the linux distributions.



### Jenkins scripted build pipeline for FreeRADIUS

The files in this directory are meant to be run by
[Jenkins](https://jenkins.io/) and make use of [the docker
plugin](https://plugins.jenkins.io/docker-workflow)  to build freeradius
packages for multiple different linux distributions in parallel.  To run this
file in Jenkins you can just add a new pipeline job and point it at 
`scripts/jenkins/Jenkinsfile`

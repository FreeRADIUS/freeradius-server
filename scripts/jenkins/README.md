### Jenkins scripted build pipeline for FreeRADIUS

The files in this directory are meant to be run by
[Jenkins](https://jenkins.io/) and make use of [the docker
plugin](https://plugins.jenkins.io/docker-workflow)  to build freeradius
packages for multiple different linux distributions in parallel.  To run this
file in Jenkins you can just add a new pipeline job and point it at 
`scripts/jenkins/Jenkinsfile`

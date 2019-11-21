#
#	Docker-related targets
#
.PHONY: docker
docker:
	docker build scripts/docker/ubuntu18 --build-arg=release=release_`echo $(RADIUSD_VERSION_STRING) | tr .- __` -t freeradius/freeradius-server:$(RADIUSD_VERSION_STRING)
	docker build scripts/docker/alpine --build-arg=release=release_`echo $(RADIUSD_VERSION_STRING) | tr .- __` -t freeradius/freeradius-server:$(RADIUSD_VERSION_STRING)-alpine

.PHONY: docker-push
docker-push: docker
	docker push freeradius/freeradius-server:$(RADIUSD_VERSION_STRING)
	docker push freeradius/freeradius-server:$(RADIUSD_VERSION_STRING)-alpine

.PHONY: docker-tag-latest
docker-tag-latest: docker
	docker tag freeradius/freeradius-server:$(RADIUSD_VERSION_STRING) freeradius/freeradius-server:latest
	docker tag freeradius/freeradius-server:$(RADIUSD_VERSION_STRING)-alpine freeradius/freeradius-server:latest-alpine

.PHONY: docker-push-latest
docker-push-latest: docker-push docker-tag-latest
	docker push freeradius/freeradius-server:latest
	docker push freeradius/freeradius-server:latest-alpine

.PHONY: docker-publish
docker-publish: docker-push-latest

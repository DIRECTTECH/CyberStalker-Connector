VERSION=$(shell cat VERSION)
IMAGE=pix-http-bridge
REGISTRY=pixelcore.azurecr.io

docker:
	docker build . -t ${IMAGE}:latest -t ${IMAGE}:${VERSION} -t ${REGISTRY}/${IMAGE}:latest -t ${REGISTRY}/${IMAGE}:${VERSION}

stable-docker:
	docker build . -t ${IMAGE}:latest -t ${IMAGE}:${VERSION} -t ${REGISTRY}/${IMAGE}:latest -t ${REGISTRY}/${IMAGE}:${VERSION} -t ${REGISTRY}/${IMAGE}:stable

# Deploy images to the registry
deploy:
	docker push ${REGISTRY}/${IMAGE}:latest
	docker push ${REGISTRY}/${IMAGE}:${VERSION}

# Update local repository
pull:
	git pull

# Bump version
bump: pull
	docker run --rm -v "${CURDIR}":/app treeder/bump patch

taggit:
	cat VERSION
	echo $(VERSION)
	git add VERSION 
	git commit -m "version $(VERSION)"
	git tag -a "$(VERSION)" -m "version $(VERSION)"
	git push 
	git push origin $(VERSION) --tags

# Trigger CI/CD procedure
version: bump taggit
	
push:
	git push origin develop
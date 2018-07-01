.DEFAULT_GOAL := default

all: pamldapd-x86-64 pamldapd-i386
default: pamldapd-x86-64
pamldapd-x86-64: x86-64.build Dockerfile_x86-64
pamldapd-i386: i386.build Dockerfile_i386
%.build: src/pamldapd.go
	@echo BUILD ARCH $(shell basename $@ .build)
	docker build -t pamldapd-build-$(shell basename $@ .build)-tmp -f Dockerfile_$(shell basename $@ .build) .
	docker run --name pamldapd-build-$(shell basename $@ .build)-tmp pamldapd-build-$(shell basename $@ .build)-tmp
	docker wait pamldapd-build-$(shell basename $@ .build)-tmp
	docker cp pamldapd-build-$(shell basename $@ .build)-tmp:/root/go/src/pamldapd pamldapd-$(shell basename $@ .build)
	docker rm pamldapd-build-$(shell basename $@ .build)-tmp

clean: x86-64.clean i386.clean
%.clean:
	@echo CLEAN ARCH $(shell basename $@ .build)
	docker rmi pamldapd-build-$(shell basename $@ .build)-tmp || true

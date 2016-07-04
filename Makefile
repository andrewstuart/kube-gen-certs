REG=docker.astuart.co:5000
IMAGE=kube-gen-certs

.PHONY: build push deploy

TAG=$(REG)/$(IMAGE)

build:
	go build
	docker build -t $(TAG) .

push: build
	docker push $(TAG)

deploy: push
	kubectl delete po -l app=kube-gen-certs

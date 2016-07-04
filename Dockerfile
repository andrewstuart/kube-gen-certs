# FROM golang:onbuild

FROM golang

CMD /kube-gen-certs

COPY kube-gen-certs /

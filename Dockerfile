FROM golang:onbuild

#
# FROM docker.astuart.co:5000/golang/shared

# RUN mkdir -p /go/src/app
# WORKDIR /go/src/app

# # this will ideally be built by the ONBUILD below ;)
# CMD ["go-wrapper", "run"]

# COPY . /go/src/app
# RUN go-wrapper download
# RUN go-wrapper install -linkshared

FROM oci.stackable.tech/sdp/ubi9-rust-builder AS builder

FROM registry.access.redhat.com/ubi9/nodejs-20-minimal@sha256:d20b9ccb915d538ea4a22f254ea9d19f1185f627c1c61747597c2896a053a915 AS operator


ARG VERSION
ARG RELEASE="1"

USER root

RUN microdnf update -y && microdnf install -y tar && microdnf clean all && mkdir /stackable


COPY csaf_validator /csaf_validator
RUN cd /csaf_validator && npm install

COPY --from=builder /app/csaf_publisher /

WORKDIR /stackable
USER 1001

ENTRYPOINT ["/csaf_publisher"]

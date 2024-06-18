FROM docker.stackable.tech/stackable/ubi8-rust-builder AS builder

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.9@sha256:87bcbfedfd70e67aab3875fff103bade460aeff510033ebb36b7efa009ab6639 AS operator


ARG VERSION
ARG RELEASE="1"

# Update image
RUN microdnf update -y && microdnf clean all && \
    groupadd --gid 1000 --system stackable && \
    useradd --gid stackable --uid 1000 --system stackable -d /stackable && \
    mkdir /stackable && \
    chown stackable:stackable /stackable

COPY --from=builder /app/csaf_publisher  /

WORKDIR /stackable
USER stackable

ENTRYPOINT ["/csaf_publisher"]

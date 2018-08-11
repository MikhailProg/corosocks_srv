# Building corosocks
FROM alpine:latest as builder
RUN apk add --no-cache gcc make musl-dev
COPY ./src/ /usr/src/corosocks/
WORKDIR /usr/src/corosocks
RUN make

# Copying binary and deploying to final image
FROM alpine:latest as runner
WORKDIR /srv/corosocks
COPY --from=builder /usr/src/corosocks/corosocks_srv .
EXPOSE 1080
CMD ["./corosocks_srv"]
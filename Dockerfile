# ----------  build stage  ----------
FROM alpine:latest AS builder
RUN apk add --no-cache clang lld musl-dev curl

# ----------  serve stage  ----------
FROM alpine:latest
RUN apk add --no-cache python3

WORKDIR /out
COPY --from=builder /usr/bin/clang* /usr/bin/lld /usr/bin/
COPY compile.sh /usr/local/bin/compile.sh
RUN chmod +x /usr/local/bin/compile.sh

EXPOSE 8080
CMD ["python3","-m","http.server","8080"]
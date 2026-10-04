FROM alpine:3.22
LABEL sem.worker-access-test="true"
RUN printf 'build command passed\n' > /build-result
CMD ["/bin/sh", "-c", "cat /build-result"]

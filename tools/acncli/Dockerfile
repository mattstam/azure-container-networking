FROM golang as build
WORKDIR /go/src/github.com/Azure/azure-container-networking/
ADD . . 
ARG VERSION
RUN make all-binaries
RUN make acncli
RUN rm -rf ./output/windows*
RUN rm -rf ./output/linux_amd64/npm/*
RUN mv ./output /output
RUN find /output -name "*.zip" -type f -delete
RUN find /output -name "*.tgz" -type f -delete

FROM scratch
COPY --from=build /output/linux_amd64/acncli/ .
COPY --from=build /output /output

ENTRYPOINT ["./acn", "cni", "manager", "--follow", "--mode", "transparent"]

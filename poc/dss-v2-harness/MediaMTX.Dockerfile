# Custom MediaMTX with FFmpeg for H.265 streaming
# Use a base image with shell, then copy mediamtx binary
FROM alpine:3.19 AS builder

# Install FFmpeg and curl
RUN apk add --no-cache ffmpeg curl

# Download MediaMTX
RUN curl -L https://github.com/bluenviron/mediamtx/releases/download/v1.11.3/mediamtx_v1.11.3_linux_amd64.tar.gz | tar xz

# Final stage - minimal image
FROM alpine:3.19
RUN apk add --no-cache ffmpeg libgcc libstdc++

# Copy MediaMTX binary
COPY --from=builder /mediamtx /mediamtx
COPY --from=builder /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=builder /usr/lib/libstdc++.so.6 /usr/lib/

# Copy config
COPY mediamtx.yml /mediamtx.yml

EXPOSE 8554 1935 8888 8889

ENTRYPOINT ["/mediamtx", "/mediamtx.yml"]
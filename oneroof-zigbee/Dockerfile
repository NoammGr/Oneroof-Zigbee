# Hardened, minimal image. No bashio, no s6, no shell beyond what the HA
# supervisor needs; one Python process, non-root.
#
# Builds from the add-on folder alone (Home Assistant's build context): the
# gateway package is installed from this repository's release tarball for the
# add-on's own version (BUILD_VERSION is passed by the Supervisor / CI).
ARG BUILD_FROM=python:3.12-alpine
FROM ${BUILD_FROM} AS build
ARG BUILD_VERSION
ARG SOURCE_REPO=https://github.com/NoammGr/Oneroof-Zigbee

RUN apk add --no-cache build-base libffi-dev openssl-dev rust cargo
RUN pip install --no-cache-dir --prefix=/install \
      "oneroof-zigbee @ ${SOURCE_REPO}/archive/refs/tags/v${BUILD_VERSION}.tar.gz" \
      pyserial-asyncio cryptography pyyaml

FROM ${BUILD_FROM}
# Only runtime libs; no compilers, no package manager cache, no git, no curl.
RUN apk add --no-cache libffi openssl eudev-libs \
    && addgroup -S -g 1000 oneroof \
    && adduser  -S -u 1000 -G oneroof -G dialout -h /nonexistent -s /sbin/nologin oneroof \
    && mkdir -p /data && chown oneroof:oneroof /data
COPY --from=build /install /usr/local
COPY run.py /run.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=random
USER oneroof
WORKDIR /data
# HEALTHCHECK without curl: the gateway touches /data/.healthy every 30 s.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
  CMD python -c "import os,sys,time; sys.exit(0 if time.time()-os.stat('/data/.healthy').st_mtime < 120 else 1)"
ENTRYPOINT ["python", "/run.py"]

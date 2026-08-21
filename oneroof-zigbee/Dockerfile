# Minimal, non-root image built by the Home Assistant Supervisor on the user's
# host (or by the release workflow). Works on any Alpine base: Python and the
# compiled dependencies come from Alpine packages (no Rust/C build step), only
# the gateway itself and one pure-Python dependency are installed with pip.
#
# The gateway package is installed from this repository's release tarball for
# the add-on's own version (BUILD_VERSION is passed by the Supervisor / CI).
ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM ${BUILD_FROM}
ARG BUILD_VERSION
ARG SOURCE_REPO=https://github.com/NoammGr/Oneroof-Zigbee

RUN apk add --no-cache python3 py3-pip py3-setuptools py3-wheel py3-cryptography py3-yaml py3-pyserial eudev-libs \
    && pip install --no-cache-dir --break-system-packages --no-deps --no-build-isolation \
         pyserial-asyncio \
         "oneroof-zigbee @ ${SOURCE_REPO}/archive/refs/tags/v${BUILD_VERSION}.tar.gz" \
    && apk del --no-cache py3-pip \
    && addgroup -S -g 1000 oneroof \
    && adduser  -S -u 1000 -G oneroof -G dialout -h /nonexistent -s /sbin/nologin oneroof \
    && mkdir -p /data && chown oneroof:oneroof /data

COPY run.py /run.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=random
USER oneroof
WORKDIR /data
# HEALTHCHECK without curl: the gateway touches /data/.healthy every 30 s.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
  CMD python3 -c "import os,sys,time; sys.exit(0 if time.time()-os.stat('/data/.healthy').st_mtime < 120 else 1)"
ENTRYPOINT ["python3", "/run.py"]

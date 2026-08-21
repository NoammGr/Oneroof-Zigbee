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

# Source: the release tarball for this version; if the tag is not published yet, fall back to
# the main branch (the Auto-tag workflow creates the tag on the next push).
RUN apk add --no-cache python3 py3-pip py3-setuptools py3-wheel py3-cryptography py3-yaml py3-pyserial eudev-libs curl \
    && SRC="${SOURCE_REPO}/archive/refs/tags/v${BUILD_VERSION}.tar.gz" \
    && if ! curl -fsSL -o /tmp/src.tar.gz "$SRC"; then \
         echo "NOTICE: release tag v${BUILD_VERSION} not found, building from main branch instead"; \
         curl -fsSL -o /tmp/src.tar.gz "${SOURCE_REPO}/archive/refs/heads/main.tar.gz"; \
       fi \
    && pip install --no-cache-dir --break-system-packages --no-deps --no-build-isolation pyserial-asyncio /tmp/src.tar.gz \
    && rm -f /tmp/src.tar.gz \
    && apk del --no-cache py3-pip curl \
    && addgroup -S -g 1000 oneroof \
    && adduser  -S -u 1000 -G oneroof -G dialout -h /nonexistent -s /sbin/nologin oneroof \
    && mkdir -p /config && chown oneroof:oneroof /config

COPY run.py /run.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=random
USER oneroof
WORKDIR /config
# HEALTHCHECK without curl: the gateway touches /config/.healthy every 30 s.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
  CMD python3 -c "import os,sys,time; sys.exit(0 if time.time()-os.stat('/config/.healthy').st_mtime < 120 else 1)"
ENTRYPOINT ["python3", "/run.py"]

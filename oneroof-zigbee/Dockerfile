# Built by the Home Assistant Supervisor on the user's host (or by the release workflow) from
# this folder alone: the gateway package is copied in, nothing is downloaded at build time, so
# the image always contains exactly the version the add-on store shows.
# Works on any Alpine base: Python and the compiled dependencies come from Alpine packages.
ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM ${BUILD_FROM}
ARG BUILD_VERSION

RUN apk add --no-cache python3 py3-pip py3-cryptography py3-yaml py3-pyserial eudev-libs \
    && pip install --no-cache-dir --break-system-packages --no-deps pyserial-asyncio \
    && apk del --no-cache py3-pip \
    && addgroup -S -g 1000 oneroof \
    && adduser  -S -u 1000 -G oneroof -G dialout -h /nonexistent -s /sbin/nologin oneroof \
    && mkdir -p /config && chown oneroof:oneroof /config

COPY oneroof_zigbee /opt/oneroof/oneroof_zigbee
COPY run.py /run.py
# The build fails loudly if the packaged code and the add-on version disagree.
RUN python3 -c "import sys; sys.path.insert(0, '/opt/oneroof'); import oneroof_zigbee as z; \
    assert z.__version__ == '${BUILD_VERSION}', f'package {z.__version__} != add-on ${BUILD_VERSION}'; print('One Roof Zigbee', z.__version__)"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=random PYTHONPATH=/opt/oneroof
# Starts as root only to read the Supervisor's root-owned options.json and to own /config,
# then run.py drops to uid 1000 when the serial device is accessible that way.
WORKDIR /config
# HEALTHCHECK without curl: the gateway touches /config/.healthy every 30 s.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
  CMD python3 -c "import os,sys,time; sys.exit(0 if time.time()-os.stat('/config/.healthy').st_mtime < 120 else 1)"
ENTRYPOINT ["python3", "/run.py"]

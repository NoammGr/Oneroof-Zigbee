# Hardened, minimal image. No bashio, no s6, no shell in the final stage
# beyond what the HA supervisor needs; one Python process, non-root.
ARG BUILD_FROM=python:3.12-alpine
FROM ${BUILD_FROM} AS build

RUN apk add --no-cache build-base libffi-dev openssl-dev rust cargo
COPY pyproject.toml /src/
COPY oneroof_zigbee /src/oneroof_zigbee
RUN pip install --no-cache-dir --prefix=/install "/src" \
    && pip install --no-cache-dir --prefix=/install pyserial-asyncio cryptography pyyaml

FROM ${BUILD_FROM}
# Only runtime libs; no compilers, no package manager cache, no git, no curl.
RUN apk add --no-cache libffi openssl eudev-libs \
    && addgroup -S -g 1000 oneroof_zigbee \
    && adduser  -S -u 1000 -G oneroof_zigbee -G dialout -h /nonexistent -s /sbin/nologin oneroof_zigbee \
    && mkdir -p /data && chown oneroof_zigbee:oneroof_zigbee /data
COPY --from=build /install /usr/local
COPY addon/oneroof_zigbee/run.py /run.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=random
USER oneroof_zigbee
WORKDIR /data
# HEALTHCHECK without curl: the gateway touches /data/.healthy every 30 s.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
  CMD python -c "import os,sys,time; sys.exit(0 if time.time()-os.stat('/data/.healthy').st_mtime < 120 else 1)"
ENTRYPOINT ["python", "/run.py"]

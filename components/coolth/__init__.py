"""Midea V3 LAN protocol, packaged as an ESPHome component.

Carries no configuration of its own -- it exists so other components can pull
the protocol sources in by listing "coolth" in AUTO_LOAD or DEPENDENCIES, and
so the library can be consumed straight from git:

    external_components:
      - source: github://a904guy/coolth-cpp
        components: [coolth]

The C++ is plain mbedtls with no ESPHome dependency, so protocol.h/.cpp also
compile standalone -- see ../../tests.
"""

import esphome.config_validation as cv

CODEOWNERS = ["@a904guy"]

CONFIG_SCHEMA = cv.Schema({})


async def to_code(config):
    # Nothing to generate: including the component is what compiles the sources.
    pass

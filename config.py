from collections import OrderedDict
from functools import cache
from pathlib import Path

import strictyaml

versionNo = "1.3.2"


@cache
def get_config_vars() -> OrderedDict:
    """Read and return the configuration variables from the config.yaml file.

    Reads the config.yaml file and returns the configuration variables as an OrderedDict.
    If the file is not found or is not valid YAML, an empty OrderedDict is returned.

    Uses functools.cache to cache the result for performance.
    This way, any module can call this function to get the configuration variables,
    but the file only needs to be read once.
    """

    config_file: Path = Path("config.yaml")

    try:
        with config_file.open() as f:
            configvars: strictyaml.YAML = strictyaml.load(f.read())
    except FileNotFoundError:
        print("Config.yaml not found. Check the example config file and rename to 'config.yaml'.")
        return OrderedDict()
    except strictyaml.YAMLValidationError as e:
        print(f"Config.yaml is not valid YAML. Error: {e}")
        return OrderedDict()

    return configvars.data  # type: ignore reportReturnType

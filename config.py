from collections import OrderedDict
from pathlib import Path

import strictyaml

versionNo = "1.3.2"


def get_config_vars() -> OrderedDict:
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

# FabricStamp
Generates device-specific Arista configs based on a yaml file. Intended to be used in combination with CloudVision Portal.

Three variants:
  - FabricStamp.py - Output as text file in current working directory.
  - builder_FabricStamp.py - Configlet builder designed to be run from CloudVision Portal. Same as FabricStamp.py, except builds the text files as static configlets from within CVP itself. 
  - ztp_FabricStamp.py - Configlet builder designed to be run from CloudVision Portal against a device that is in ZTP mode. Will parse out the device serial number, loop through the YAML file to find a match, then build a generated configlet for the device.

Required Libraries:
  - netaddr 
  - jinja2
  - yaml
  - re

Usage:
  from directory - `python FabricStamp.py`
    - This will generate a .txt file within the directory for each device.

To-Do: Finish documentation.

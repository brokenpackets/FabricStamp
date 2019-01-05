# FabricStamp
Generates device-specific Arista configs based on a yaml file. Intended to be used in combination with Cloudvision Portal.

Required Libraries:
  - netaddr 
  - jinja2
  - yaml
  - re

Usage:
  from directory - `python FabricStamp.py`
    - This will generate a .txt file within the directory for each device.

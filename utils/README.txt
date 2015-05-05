PAN-Configurator 'utils' directory contains scripts which can run out of the box and are based on PAN-Configurator classes.

Index of scripts:

- address-edit.php : to make changes to address/group, you can use filters to make changes only to objects of interest. Makes it easy to delete unused objects for example or replace. Use argument 'help' for details and usage.

- checkpoint-exclude.php : calculate a static value for checkpoint-exlusion groups out of the migration tool. Give it the name of the group and it will consider that member #1 is the 'include' group while member #2 is the 'exclude' group and make numeric calculations to replace all members by a set of IP-ranges.

- grp-static-to-dynamic.php : converts a static group to a dynamic group by tagging its objects and replacing the group members by a query on that tag.

- rules-edit.php : mass rule editor for PANOS and Panorama, it can work on backup files on your hard drive or with API. You can filter rules to modify with a query and then apply changes to all selected rules. Use 'php rules-edit.php help' for usage details.

- rule-merger.php : script to merge similar rules together. Various options to define common criteria, adjacency limits, stop after a deny etc etc are also included.

- service-edit.php : to make changes to service/group, you can use filters to make changes only to objects of interest. Makes it easy to delete unused objects for example.

- upload-config.php : tool for easy upload/download of configuration on a PANOS device. ie: if you want to replicate a config from a device to another but just keep management IP address. Use 'help' argument for more details.




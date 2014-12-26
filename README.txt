/******************************************************************************
*
  Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
  Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com

  Permission to use, copy, modify, and distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*
******************************************************************************/

Requirement : PHP 5.4 with curl module
Use: include the file lib/panconfigurator.php in your own script to load the necessary classes.

File tree:

- /lib/ contains library files source code
- /utils/ contains ready to run scripts
- /doc/index.html  has all classes documentations
- /example-*.php are examples about using this library
- /sample-configs/ hold dummy configuration files to run examples on

PAN-Configurator is a PHP library aimed at making PANOS config changes easy (and XML free ;), maintainable and allowing complex scenarios like rule merging, unused object tracking, conversion of checkpoint exclusion groups, massive rule editing, AppID conversion … to name the ones I do on a regular basis and which are not offered by our GUI. It will work seamlessly on local config file or API.

With less than 20 lines of code, you should be able to solve most of your needs. Brief overview:

Loading a config from a file ?

   $pan = new PANConf();
   $pan->load_from_file('myconfig.xml');

Prefer to load it from API candidate config ?

   $connector = panAPIConnector::findOrCreateConnectorFromHost('fw1.mycompany.com');
   $pan = new PANConf();
   $pan->API_load_from_candidate($connector);

Delete unused objects from a config ?

   foreach($pan->addressStore->addressObjects() as $object )
     if( $object->countReferences() == 0 )
        $pan->addressStore->remove($object);

Want to know where an object is used ?

   $object = $pan->addressStore->find('H-WebServer4');
   foreach( $object->getReferencers() as $ref )
      print $ref->toString()."\n";

Replace that object by another one ?

   $object->replaceMeGlobally($anotherObject);

Want to add security profile group 'Block-Forward-Critical-High' in rules which have destination zone 'External' and source zone 'DMZ'?

   foreach( $vsys1->securityRules->rules() as $rule )
      if( $rule->from->has('DMZ') && $rule->to->has('External') )
            $rule->setSecurityProfileGroup('Block-Forward-Critical-High');

Do you hate scripting ? Utility script 'rules-edit.php' is a swiss knife to edit rules and takes advantage of PAN Configurator library from a single CLI query:

Do you want to enable log at start for rule going to DMZ zone and that has only object group 'Webfarms' as a destination ?
   rules-edit –in=api://fw1.mycompany.com –type=panos –actions=enableLogStart 'filter=(to has dmz) and (dst has.only Webfarms)'

You are not sure about your filter and want to see rules before making changes ? Use action 'display' :
   rules-edit.php  –in=api://fw1.mycompany.com –type=panos –actions=display 'filter=(to has dmz) and (dst has.only Webfarms)'

Change all rules using Application + Any service to application default ?
   rules-edit.php –in=api://fw1.mycompany.com –type=panos –actions=service-Set-AppDefault 'filter=!(app is.any) and (service is.any)'

Move post-SecurityRules with source zone 'dmz' or source object 'Admin-networks' to pre-Security rule ?
   rules-edit.php  –in=api://panorama.mycompany.com –type=panorama –actions=invertPreAndPost 'filter=((from has dmz) or (source has Admin-networks) and (rule is.postrule))'

Want to know what actions are supported ?
   rules-edit.php  listActions
   rules-edit listFilters



<?php

/*****************************************************************************
*
*	 This script is doing basic use PAN-Configurator API.
*		
*	It will load a sample PANOS config and make some rules and object 
*	editing.
*
*****************************************************************************/

// load PAN-Configurator library
require_once("../lib/panconfigurator.php");

// input and output files
$origfile = "sample-configs/policy-best-practices.xml";
$outputfile = "output.xml";


// We're going to load a PANConf object (PANConf is for PANOS Firewall,
//	PanoramaConf is obviously for Panorama which is covered in another example)
$panc = new PANConf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$vsys1 = $panc->findVirtualSystem('vsys1');
if( $vsys1 === null )
{
	derr("vsys1 was not found ? Exit\n");
}

print "\n***********************************************\n\n";


print "\n\n************ Security Rules before changes  *********\n\n";

// $vsys1->securityRules is an object containing all VSYS1 rules. Here we call display() to print them in console.
$vsys1->securityRules->display();

// Here we look for a rule named 'Mail Server incoming mails'
$mailServerRule = $vsys1->securityRules->find('Mail Server incoming mails');
// exit if that rule was not found
if( $mailServerRule === null )
    derr("ERROR : Cannot find rule 'Mail Server incoming mails'\n");

// now look for an object named 'mail-server2'
$objectMailServer2 = $vsys1->addressStore->find('mail-server2');
if( $objectMailServer2 === null )
    derr("ERROR : Cannot find object named 'mail-server2'\n");

// add 'mail-server2' in rule 'Mail Server' source.
$mailServerRule->source->addObject($objectMailServer2);


// now we rename object 'mail-server2' into mail 'mail-server3'
$objectMailServer2->setName('mail-server3');


// create a Tag called 'MAIL RULES'
$tagMailRules = $vsys1->tagStore->findOrCreate('MAIL RULES');

// add this tag to the rule 'Mail Server incoming mails'
$mailServerRule->tags->addTag($tagMailRules);

// set Security Group Profile 'SecProf2' on that rule
$mailServerRule->setSecurityProfileGroup('SecProf2');


// disable a rule
$mailServerRule->setDisabled(true);

// rename it
$mailServerRule->setName('Incoming SMTP');

// move it before 'WebFarm access'
$vsys1->securityRules->moveRuleBefore($mailServerRule,'WebFarm access');

// change action to deny
$vsys1->securityRules->find('WebFarm access')->setAction('deny');

// remove DNAT from a rule
$vsys1->natRules->find('rule7 - dnat with port')->setNoDNAT();

// add DNAT to a rule
$vsys1->natRules->find('rule5 - dynamicIP interface spe')->setDNAT($vsys1->addressStore->find('client-2-address'));

//remove Source NAT froma  rule
$vsys1->natRules->find('rule2 - static')->setNoSNAT();

// add an IP to a dynamic IP pool
$vsys1->natRules->find('rule3 - dynamic IP address')->snathosts->addObject($vsys1->addressStore->find('client-2-address'));




print "\n\n************ Security Rules after changes  *********\n\n";

$vsys1->securityRules->display();


print "\n***********************************************\n";


$panc->save_to_file($outputfile);

//display some statistics
$vsys1->display_statistics();




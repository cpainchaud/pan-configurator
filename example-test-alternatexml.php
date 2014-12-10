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
require_once("lib/shared.php");

// input and output files
$origfile = "sample-configs/panos-example-2.xml";
$outputfile = "output.xml";

PH::enableDomXMLSupport();


// We're going to load a PANConf object (PANConf is for PANOS Firewall,
//	PanoramaConf is obviously for Panorama which is covered in another example)
$panc = new PANconf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$vsys1 = $panc->findVirtualSystem('vsys1');
if( is_null($vsys1) )
{
	die("vsys1 was not found ? Exit\n");
}

print "\n***********************************************\n\n";


print "\n\n************ Security Rules before changes  *********\n\n";

$vsys1->securityRules->display();


// add some objects existing rules
$vsys1->securityRules->find('secrule1')->source->add($vsys1->addressStore->find('server-4-address'));
$vsys1->securityRules->find('secrule2')->destination->add($vsys1->addressStore->find('my address group'));

//rename an address and address group object
$vsys1->addressStore->find('server-4-address')->setName('server-4-address-afterchange');
$vsys1->addressStore->find('my address group')->setName('my address group-afterchange');

// add some tags
$vsys1->securityRules->find('secrule2')->tags->addTag('tagsec-rul3');

// set Security Profile
$vsys1->securityRules->find('secrule5')->setSecProf_AV('AV 2');

//rename a service
$vsys1->serviceStore->find('TCP-55')->setName('new service name');


// disable a rule
$vsys1->securityRules->find('secrule4')->setDisabled(true);

// and rename it
$vsys1->securityRules->find('secrule4')->setName('renamed rule');

// move it after rule 5
$vsys1->securityRules->moveRuleAfter('renamed rule','secrule5');

// change action to allow on another one
$vsys1->securityRules->find('secrule5')->setAction('allow');

// remove DNAT from a rule
$vsys1->natRules->find('rule7 - dnat with port')->setNoDNAT();

// add DNAT to a rule with port 25
$vsys1->natRules->find('rule5 - dynamicIP interface spe')->setDNAT($vsys1->addressStore->find('client-2-address'));

//remove Source NAT froma  rule
$vsys1->natRules->find('rule2 - static')->setNoSNAT();

// add an IP to a dynamic IP pool
$vsys1->natRules->find('rule3 - dynamic IP address')->snathosts->add($vsys1->addressStore->find('client-2-address'));



//
// now we want to add a zone to all rules
//   + zone 'internal' in FROM 
//   + zone 'external' in TO
// and tag them with tag 'I_WAS_TAGGED'

// first get the list of rules in an array
$rules = $vsys1->securityRules->rules();

// let's create a tag
$mytag = $vsys1->tagStore->findOrCreate('I_WAS_TAGGED');

foreach( $rules as $rule )
{
	$rule->from->addZone( $vsys1->zoneStore->find('internal') );
	$rule->to->addZone( $vsys1->zoneStore->find('external') );
	$rule->to->removeZone( $vsys1->zoneStore->find('external'), true, true );
	$rule->tags->addTag( $mytag );
}




print "\n\n************ Security Rules after changes  *********\n\n";

$vsys1->securityRules->display();


print "\n***********************************************\n";


$panc->save_to_file($outputfile);

//display some statistics
$vsys1->display_statistics();

memory_and_gc('end');



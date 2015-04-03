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


// We're going to load a PANConf object (PANConf is for PANOS Firewall,
//	PanoramaConf is obviously for Panorama which is covered in another example)
$panc = new PANconf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$vsys1 = $panc->findVirtualSystem('vsys1');
if( is_null($vsys1) )
{
	derr("vsys1 was not found ? Exit\n");
}

print "\n***********************************************\n\n";

// look for an object named server-4-address
$addressObject = $vsys1->addressStore->find('server-4-address');
// display the list of objects that are using this
$addressObject->display_references();

print "\n";

// look for an object called client-2-address
$anotherObject = $vsys1->addressStore->find('client-2-address');
// display the list of objects that are using this
$anotherObject->display_references();

print "\nAfter replacement\n\n";

// Let's replace this object by another one everywhere
$addressObject->replaceMeGlobally($anotherObject);

$addressObject->display_references();
print "\n";
$anotherObject->display_references();





print "\n***********************************************\n";


//display some statistics
$vsys1->display_statistics();




//more debugging infos

memory_and_gc('end');



<?php
/********************************************************************************************
 
 	This sample script will connect to a live firewall and do some live changes. 

*********************************************************************************************/


// load 'PAN Configurator' library
require "lib/panconfigurator.php";

$apikey = 'LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09';
$apihost = '192.168.50.10';


$con = new PanAPIConnector( $apihost, $apikey, 'panos');

// enable connector to show us API calls on the go
$con->setShowApiCalls(true);

$panc = new PANConf();
$panc->API_load_from_candidate($con);

// Did we find VSYS1 ?
$vsys1 = $panc->findVirtualSystem('vsys1');
if( is_null($vsys1) )
{
	die("vsys1 was not found ? Exit\n");
}

print "\n***********************************************\n\n";

//display rules
$vsys1->securityRules->display();

// look for an object named 'User-Networks'
$object = $vsys1->addressStore->find('User-Networks');
if( is_null($object) )
	die("Error: object not found\n");

// want to know xpath of an object ?
print "displaying XPATH of object named ".$object->name()." : ".$object->getXPath()."\r\n";

// let's rename it in API
$object->API_setName('another-name');

$rule = $vsys1->securityRules->find('Mail Server');
if( is_null($rule) )
	die("Error: rule nor found\n");

// add an object to this rule Source through API
$rule->source->API_add($object);

// set Destination to Any
$rule->destination->API_setAny();

// remove object from another rule Source
$rule = $vsys1->securityRules->find('Exception SSH for Dev');
if( is_null($rule) )
	die("Error: rule nor found\n");
$rule->source->API_remove($object);

// uplaod config directly to the device !!!
//$panc->API_uploadConfig('test-config1.xml');


// display some statiscs for debug and exit program!
print "\n\n***********************************************\n";
$vsys1->display_statistics();




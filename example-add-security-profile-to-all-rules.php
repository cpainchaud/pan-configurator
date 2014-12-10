<?php

/*****************************************************************************
*
*	This script will list all rules in vsys  et and make them use
*       security group $targetProfile
*		
*	
*	
*
*****************************************************************************/

// load PAN-Configurator library
require_once("lib/shared.php");

// input and output files
$origfile = "sample-configs/policy-best-practices.xml";
$targetVSYS = 'vsys1';
$targetProfile = 'SecProf1';
$outputfile = "output.xml";


// We're going to load a PANConf object (PANConf is for PANOS Firewall,
$panc = new PANconf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$vsys1 = $panc->findVirtualSystem($targetVSYS);
if( is_null($vsys1) )
{
	die("vsys1 was not found ? Exit\n");
}

print "\n***********************************************\n\n";


// first get the list of rules in an array
$rules = $vsys1->securityRules->rules();


// for every rule we set the security profile
foreach( $rules as $rule )
{
    print "- Updating rule '".$rule->name()."' with security profile '$targetProfile'\n";
	$rule->setSecurityProfileGroup($targetProfile);
}



print "\n***********************************************\n";

// Save resulting config to a file
$panc->save_to_file($outputfile);

//display some statistics
$vsys1->display_statistics();



//more debugging infos

memory_and_gc('end');




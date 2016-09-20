<?php

/*****************************************************************************
 *
 *	This script will list all rules in DeviceGroup referenced in $targetDG
 * and force them into using profile group referenced in $targetProfile
 *
 *
*****************************************************************************/

// load PAN-Configurator library
require_once("../lib/panconfigurator.php");

// input and output files
$origfile = "sample-configs/panorama-example.xml";
$outputfile = "output.xml";

$targetDG = 'Perimeter-FWs';
$targetProfile = 'Shared Production Profile';

// We're going to load a PANConf object (PANConf is for PANOS Firewall,
//	PanoramaConf is obviously for Panorama which is covered in another example)
$panc = new PanoramaConf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$dg = $panc->findDeviceGroup($targetDG);
if( $dg === null )
{
	derr("DeviceGroup {$targetDG} was not found ? Exit\n");
}

print "\n***********************************************\n\n";


// Going after each pre-Security rules to add a profile
foreach( $dg->securityRules->rules() as $rule )
{
    print "Rule '".$rule->name()."' modified\n";
    $rule->setSecurityProfileGroup($targetProfile);
}


print "\n***********************************************\n";


$panc->save_to_file($outputfile);

//display some statistics
$panc->display_statistics();



//more debugging infos

memory_and_gc('end');




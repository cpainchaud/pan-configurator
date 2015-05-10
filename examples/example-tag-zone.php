<?php

// load 'PAN Configurator' library
require_once("../lib/panconfigurator.php");

/********************************************************************************************
 
 	This sample script will look for all rules inside a Panorama config and search for
 	tags Outgoing or Incoming.
 	
 	When Outgoing is found, it will edit the rule to put FromZone = internal and
 							     ToZone = external
 							     
 	When Incoming is found, it will edit the rule to put FromZone = extern and
 							     ToZone = internal						     

*********************************************************************************************/



// input and ouput xml files
$inputfile = 'sample-configs/panorama-example.xml';
$outputfile = 'output.xml';


// Create a new PanoramaConf object
$p = new PanoramaConf();
// and load it from a XML file
$p->load_from_file($inputfile);
print "\n***********************************************\n\n";


// below starts the real stuff

// we need to find references of Zones 'internal' and 'external'. they will be used later
$internal = $p->zoneStore->find('internal');
$external = $p->zoneStore->find('external');

if( !$internal )
	derr("We didn't find zone 'internal', is there a problem? \n");
if( !$external )
	derr("We didn't find zone 'external', is there a problem? \n");


// We are looking for a tag called "Outgoing" , to be used later, same for Incoming tag
$outgoing = $p->tagStore()->find('Outgoing');
if( !$outgoing )
	derr("We didn't find tag Outgoing, is there a problem? \n");

// We are looking for a tag called "Incoming"
$incoming = $p->tagStore()->find('Incoming');
if( !$incoming )
	derr("We didn't find tag Incoming, is there a problem? \n");


/*****************************************
 Let's process rules with Outgoing tag
******************************************/

// How many times is this tag used globally ?
$countref = $outgoing->countReferences();
print "Tag named '".$outgoing->name()."' is used in $countref places\n";

// But we need to filter these references to extract SecurityRule only
$list = $outgoing->findAssociatedSecurityRules();
// how many references left after filtering?
$countref = count($list);
$total = $countref;
print "Tag named '".$outgoing->name()."' is used in $countref SecurityRules\n";

// Now we need to look at each rule and change it's source and destination zones
foreach ($list as $rule)
{
    // print rulename for debug, comment them if you want
    print "     Rule named '".$rule->name()."' from DeviceGroup '".$rule->owner->name()."' with tag '".$incoming->name()."' has the following Zones:\n";
    print "        From: ".$rule->from->toString_inline()."\n";
    print "        To:   ".$rule->to->toString_inline()."\n";
    
    // now we check if each rule has internal in source zone and external in destination zone
    if( ! $rule->from->hasZone($internal) )
    {
    	    print "          This rule needs source zone to be added\n";
    	    $rule->from->addZone($internal);
    	    print "          Updated From: ".$rule->from->toString_inline()."\n";
    }
    if( ! $rule->to->hasZone($external) )
    {
    	    print "          This rule needs destination zone to be added\n";
    	    $rule->to->addZone($external);
    	    print "          Updated To: ".$rule->to->toString_inline()."\n";
    }
    
    print "\n";
    
}


/*****************************************
 Now rules with Incoming Tag
******************************************/
// How many times is this tag used globally ?
$countref = $incoming->countReferences();
$total += $countref;
print "Tag named '".$incoming->name()."' is used in $countref places\n";

// But we need to filter these references to extract SecurityRule only
$list = $incoming->findAssociatedSecurityRules();
// how many references left after filtering?
$countref = count($list);
print "Tag named '".$incoming->name()."' is used in $countref SecurityRules\n";

// Now we need to look at each rule and change it's source and destination zones
foreach ($list as $rule)
{
    // print rulename for debug, comment them if you want
    print "     Rule named '".$rule->name()."' from DeviceGroup '".$rule->owner->name()."' with tag '".$incoming->name()."' has the following Zones:\n";
    print "        From: ".$rule->from->toString_inline()."\n";
    print "        To:   ".$rule->to->toString_inline()."\n";
    
    // now we check if each rule has internal in source zone and external in destination zone
    if( ! $rule->from->hasZone($external) )
    {
    	    print "          This rule needs needs source zone to be added\n";
    	    $rule->from->addZone($external);
    	    print "          Updated From: ".$rule->from->toString_inline()."\n";
    }
    if( ! $rule->to->hasZone($internal) )
    {
    	    print "          This rule needs needs destination zone to be added\n";
    	    $rule->to->addZone($internal);
    	    print "          Updated To: ".$rule->to->toString_inline()."\n";
    }
    
    print "\n";
    
}


print "We have edited a total of $total SecurityRules\n\n";


// save resulting configuration file to output.xml
$p->save_to_file($outputfile);


// display some statiscs for debug and exit program!
print "\n\n***********************************************\n";
$p->display_statistics();

memory_and_gc('end');



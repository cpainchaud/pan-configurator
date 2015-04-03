<?php

// load 'PAN Configurator' library
require "lib/panconfigurator.php";

/***************************************************************

 

****************************************************************/


// input and ouput xml files
$inputfile = 'sample-configs/panorama-example4.xml';
$outputfile = 'output.xml';


// Create a new PanoramaConf object
$p = new PanoramaConf();
// and load it from a XML file
$p->load_from_file($inputfile);

print "\n***********************************************\n\n";



// variable to count unused objects
$countUnused = 0;

// we put all central stores in an array

// first the Shared one
$centralstores[] = $p->addressStore;

foreach( $p->deviceGroups as $dv )
	$centralstores[] = $dv->addressStore;


foreach( $centralstores as $store )
{
	print "-- Handling store '".$store->toString()."'\n";
	$objects = $store->all();

	foreach( $objects as $o)
	{
		$classname = get_class($o);
		if( $classname == "Address" )
		{
			// If it's a tmp object , we ignore it
			if( $o->isTmpAddr() )
			{
				continue;
			}
			if( $o->countReferences() == 0 )
			{
				print "unused object found: ".$o->toString()."\n";
				$countUnused++;
			}
		}
		elseif( $classname == "AddressGroup" )
		{
			if( $o->countReferences() == 0 )
			{
				print "unused object found: ".$o->toString()."\n";
				$countUnused++;
			}
		}
		else
			derr("this class of object is not supported!");
	}

	print "\n\n";
}

print "\n\nFound $countUnused unused objects\n\n";


// display some statiscs for debug and exit program!
print "\n\n***********************************************\n";
$p->display_statistics();




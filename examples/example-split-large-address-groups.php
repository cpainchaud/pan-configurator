<?php

/********************************************************************************************
 
 	This sample script will look for all address groups in each Device Groups or VSYS and split
 	the ones which have more than 491 members into subgroups of 490 members each. 
 	
 	These numbers can be manipulated with the variables: $largeGroupsCount and
 	$splitCount 
 	
 	If you are going to edit a Panorama configuration, change variable $mode='panorama' ,
 	 otherwise change it to $mode = 'panos'
 	
 	Note that future versions of this library may include a single function to do this
 	automatically

*********************************************************************************************/


// load 'PAN Configurator' library
require_once("../lib/panconfigurator.php");

//$mode = 'panos';
$mode = 'panorama';

// input and ouput xml files
$inputfile = 'sample-configs/panorama-example4.xml';
$outputfile = 'output.xml';

$largeGroupsCount  = 491;
$splitCount = 490;

// is it a Panorma or PANOS config ?
if( $mode == 'panorama' )
{
	// Create Panorama object
	$p = new PanoramaConf();

	// and load it from a XML file
	$p->load_from_file($inputfile);
	
	// load the list of DeviceGroups in an array
	$subs = $p->deviceGroups;

	
}
else if( $mode == 'panos')
{
	// Create new PanConf object
	$p = new PANConf();
	
	// load it from XML file
	$p->load_from_file($inputfile);
	
	// load the list of VSYS in an array
	$subs = $p->virtualSystems;
	
}
else 
	derr('Please set mode="panos" or mode ="panorama"');
	

print "\n***********\n\n";


// For every VSYS/DeviceGroups we're going to list Groups and count their members.
foreach($subs as $sub )
{
	print "Found DeviceGroup/VirtualSystem named '".$sub->name()."'\n";
	
	$countGroups = $sub->addressStore->countAddressGroups();
	
	print "  Found $countGroups AddressGroups in this DV";
	
	$Groups = $sub->addressStore->addressGroups();
	
	foreach( $Groups as $group )
	{
		$membersCount = $group->count();
		
		// if this group has more members than $largeGroupsCount then we must split it
		if( $membersCount > $largeGroupsCount )
		{
			print "     AddressGroup named '".$group->name()."' with $membersCount members \n";
			
			// get member list in $members
			$members = $group->members();
			
			$i=0;

            if( isset($newGroup) ) unset($newGroup);
			
			// loop move every member to a new subgroup
			foreach( $members as $member )
			{
				// Condition to detect if previous sub-group is full
				// so we have to create a new one
				if( $i%$splitCount == 0 )
				{
					if( isset($newGroup) )
					{ // now we can rewrite XML
						$newGroup->rewriteXML();
					}

					// create a new sub-group with name 'original--1'
					$newGroup = $sub->addressStore->newAddressGroup( $group->name().'--'.($i/$splitCount) );
					print "      New AddressGroup object created with name: ".$newGroup->name()."\n";

					// add this new sub-group to the original one. Don't rewrite XML for performance reasons.
					$group->add($newGroup, false);
				}
				
				// remove current group member from old group, don't rewrite XML yet for performance savings
				$group->remove( $member, false );

				// we add current group member to new subgroup
				$newGroup->add( $member, false );
				
				$i++;
			}
            if( isset($newGroup) )
            { // now we can rewrite XML
                $newGroup->rewriteXML();
            }
			
			// Now we can rewrite XML
			$group->rewriteXML();

			print "     AddressGroup count after split: ".$group->count()." \n";
			
			print "\n";
			
		}
	}
	
}


print "\n\n";


$p->save_to_file($outputfile);




<?php

/******************************************************************************
*
*	author: Christophe Painchaud (cpainchaud@palolaltonetworks.com)
*   (c) Palo Alto Networks
*
*   This script resolves Checkpoint Exclusion Groups into static objects, usually
*  used after MT2.4 has done its job.
*   You feed it with a location/groupname or a list.txt file if you want several
*  groups to be converted.
*
*        !!!! WARNING !!! Since PANOS doesn't support exclusion groups , your
*  customer must be warned that any change he makes to previously used objects
*  will have no effect on resulting groups. HE STILL HAVE TO FIND A LONG TERM
*  SOLUTION.
*
******************************************************************************/

set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");


function display_usage_and_exit()
{
    global $argv;
    print "\nusage: php ".basename(__FILE__)." type=panos|panorama in=inputfile.xml out=outputfile.xml location=shared|sub ".
        "group=groupName||groupfile=listGroupFile.txt\n".
		"Example: php ".basename(__FILE__)." type=panos in=original.xml out=final.xml location=shared group=group_internal_excl_dmz\n".
		"         php ".basename(__FILE__)." type=panorama in=original.xml out=final.xml location=dmz-firewalls groupfile=grouplist.txt\n\n";
    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, "\n\n**ERROR** ".$msg."\n\n");
    display_usage_and_exit();
}

// load arguments in PH::$args for easy use
PH::processCliArgs();

//default values
$cliType = null;
$groupName = null;
$groupLocation = null;
$groupFile = null;
$inputFile = null;
$outputFile = null;


if( ! isset(PH::$args['type']) )
    display_error_usage_exit('"type" is missing from arguments');


if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$inputFile = PH::$args['in'];
if( !is_string($inputFile) || strlen($inputFile) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');


if( ! isset(PH::$args['out']) )
    display_error_usage_exit('"out" is missing from arguments');
$outputFile = PH::$args['out'];
if( !is_string($outputFile) || strlen($outputFile) < 1 )
    display_error_usage_exit('"out" argument is not a valid string');


if( isset(PH::$args['location']) && !isset(PH::$args['group'])   )
    display_error_usage_exit('"location" argument is set but no "group" argument was provided');

if( isset(PH::$args['group']) && isset(PH::$args['groupfile']) )
    display_error_usage_exit('"groupfile" and "group" arguments are exclusive');

if( !isset(PH::$args['group']) && !isset(PH::$args['groupfile']) )
    display_error_usage_exit('"groupfile" or "group" is missing from arguments');

if( isset(PH::$args['groupfile']) )
{
    $groupFile = PH::$args['groupfile'];
    if( !is_string($groupFile) || strlen($groupFile) < 1 )
        display_error_usage_exit('"groupfile" argument is not a valid string');

}

if( isset(PH::$args['group']) )
{
    $groupName = PH::$args['group'];
    if( !is_string($groupName) || strlen($groupName) < 1 )
        display_error_usage_exit('"group" argument is not a valid string');

    if( isset(PH::$args['location']) )
    {
        $groupLocation = PH::$args['location'];
        if( !is_string($groupLocation) || strlen($groupLocation) < 1 )
            display_error_usage_exit('"group" argument is not a valid string');
    }
    else
    {
        print " notice : missing argument 'location', assuming 'shared'\n";
        $groupLocation = 'shared';
    }
}


//
//
//  Script really starts here
//

$configType = strtolower(PH::$args['type']);

if( $configType != 'panos' && $configType != 'panorama' )
	derr("\n**ERROR** Unsupported config type '$configType'. Check your CLI arguments\n\n");

print "Config type is '$configType', intput filename is '$inputFile'\n";

if( !file_exists($inputFile) )
	derr("\n**ERROR** Input file '".$inputFile."' doesn't exists!\n\n");



print "Loading config file '".$inputFile."'... ";
if( $configType == 'panos' )
{
	$pan = new PANConf();
}
else
{
	$pan = new PanoramaConf();
}
$pan->load_from_file($inputFile);
print "OK!\n\n";


// Variable that will hold all groups to be processed
$groupsToProcess = Array();

// if $argv[4] is a file that exists then we must load it
if( $groupFile !== null )
{
	$fcontent = file_get_contents($groupFile);
	$groupsToProcess = explode("\n", $fcontent);
}
else
{
	$groupsToProcess[] = $groupLocation.'/'.$groupName;
}

print "Sanitizing and listing groups from input:\n";
foreach( $groupsToProcess as $index => &$group )
{
	if( strlen($group) < 3 )
		unset($groupsToProcess[$index]);

	$expl = explode('/', $group);
	if( count($expl) != 2)
	{
		print " * group '$group' has no location set, assuming";
		$group = 'shared/'.$group;
		print " '$group'\n";
	}
	else
	{
		print " - '$group'\n";
	}
}
unset($group);
print "Listing done\n\n";


print "**Now processing each group one by one to calculation exclusions**\n\n";

foreach( $groupsToProcess as $group )
{
	$expl = explode('/', $group);
    print "* Group '$expl[1]' from location '$expl[0]'\n";


    //
    // looking for AddressStore that is holding our group
    //
    if( $expl[0] == 'shared' )
    {
    	$store = $pan->addressStore;
    }
    else
    {
    	if( $configType == 'panos' )
    	{
    		$sub = $pan->findVirtualSystem($expl[0]);
    		if( $sub === null )
    			derr("  ***ERROR*** cannot find VSYS '$expl[0]'\n\n");
    	}
    	else
    	{
    		$sub = $pan->findDeviceGroup($expl[0]);
    		if( $sub === null )
    			derr("  ***ERROR*** cannot find DeviceGroup '$expl[0]'\n\n");
    	}
    	$store = $sub->addressStore;
    }


    //
    // Looking for the group inside the AddressStore we found
    //
    $groupToProcess = $store->find($expl[1], null, false);
    if( $groupToProcess === null )
    	derr("  ***ERROR*** cannot find group '$expl[1]' in location '$expl[0]'\n\n");

    //
    // checking this group has 2 members, one will be the $incGroup , the other will be the $exclGroup
    //
    $members = $groupToProcess->members();
    if( count($members) != 2 )
    	derr("  ***ERROR*** that group doesn't have 2 members\n\n");
    $membersKeys = array_keys($members);
    $incGroup = $members[$membersKeys[0]];
    $exclGroup = $members[$membersKeys[1]];
    print "   * incGroup is '".$incGroup->name()."' and excGroup is '".$exclGroup->name()."'\n";
    $incGroupExpanded = $incGroup->expand();
    $exclGroupExpanded = $exclGroup->expand();

    // create IP mappings for all objects
    foreach( $incGroupExpanded as $index => $object )
    {
    	$res = $object->resolveIP_Start_End();
    	$incGroupExpanded[$index] = Array('object'=>$object, 'start'=>$res['start'],
    	'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']), 'status'=>0);
    }
    foreach( $exclGroupExpanded as $index => $object )
    {
    	$res = $object->resolveIP_Start_End();
    	$exclGroupExpanded[$index] =Array('object'=>$object, 'start'=>$res['start'],
    	'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']) );
    }

    //
    //  Now we need to match all excl vs inc objects
    //
    foreach( $exclGroupExpanded as $index => &$excl )
    {
    	print "     ** Processing excl object '".$excl['object']->name()." (".$excl['startip']."-".$excl['endip'].")'\n";
    	foreach( $incGroupExpanded as &$incl )
    	{
    		// this object was already fully matched so we skip
    		if( $incl['status'] == 2 ) continue;

    		print "       - against '".$incl['object']->name()."' ".$incl['startip']."-".$incl['endip']." ... ";
		
			if( $incl['start'] >= $excl['start'] && $incl['end'] <= $excl['end'] )
	    	{
	    		print "FULL match\n";
	    		$incl['status'] = 2;
	    	}
	    	elseif( $incl['start'] >= $excl['start'] &&  $incl['start'] <= $excl['end'] || 
	    		$incl['end'] >= $excl['start'] && $incl['end'] <= $excl['end'] ||
	    		$incl['start'] <= $excl['start'] && $incl['end'] >= $excl['end'] )
	    	{
	    		print "PARTIAL match\n";
	    		$incl['status'] = 1;
	    	}
	    	else
	    		print "NO match\n";
	    }

    	print "\n";
    }

    //
    // First filter is done, now we make a list of Incl objects :
    //		- Partial matches, these ones will require special treatment
    //		- FULL matches, these ones will not be included in final group
    //		- NO matches, these ones will be included in final group
    //
    $inclPartial = Array();
    $inclNo = Array();
    print "   * Sorting incl objects in Partial and No arrays\n";
    foreach( $incGroupExpanded as &$incl )
    {
    	if( $incl['status'] == 1 )
    	{
    		print "     - obj '".$incl['object']->name()."' is PARTIAL\n";
    		$inclPartial[] = &$incl;
    	}
    	elseif( $incl['status'] == 2 )
    	{
    		print "     - obj '".$incl['object']->name()."' is NO match\n";
    		$inclNo[] = &$incl;
    	}
    }

    //
    // Sort incl objects IP mappings by Start IP
    //
    print "\n   * Sorting incl obj by StartIP\n";
    $inclMapping = Array();
    $tmp = Array();
    foreach($inclPartial as &$incl)
    {
    	$tmp[] = $incl['start'];
    }
    unset($incl);
    sort($tmp, SORT_NUMERIC);
    foreach($tmp as $value)
    {
    	foreach($inclPartial as &$incl)
    	{
    		if( $value == $incl['start'] )
    		{
    			print "     -'".$incl['object']->name()." (".$incl['startip']."-".$incl['endip'].")'\n";
    			$inclMapping[] = $incl;
    		}
    	}
    }
    unset($incl);

	//
    // Sort incl objects IP mappings by Start IP
    //
    print "\n   * Sorting excl obj by StartIP\n";
    $exclMapping = Array();
    $tmp = Array();
    foreach($exclGroupExpanded as &$excl)
    {
    	$tmp[] = $excl['start'];
    }
    unset($excl);
    sort($tmp, SORT_REGULAR);
    foreach($tmp as $value)
    {
    	foreach($exclGroupExpanded  as &$excl)
    	{
    		if( $value == $excl['start'] )
    		{
    			print "     -'".$excl['object']->name()." (".$excl['startip']."-".$excl['endip'].")'\n";
    			$exclMapping[] = $excl;
    		}
    	}
    }
    unset($excl);

    //
    // Merge overlapping or Incl joint entries
    //
    print "\n   * Merging overlapping Incl entries\n";
    $mapKeys = array_keys($inclMapping);
    $mapCount = count($inclMapping);
    for( $i=0; $i<$mapCount; $i++)
    {
    	$current = &$inclMapping[$mapKeys[$i]];
    	print "     - handling ".$current['startip']."-".$current['endip']."\n";
    	for( $j=$i+1; $j<$mapCount; $j++)
    	{
    		$compare = &$inclMapping[$mapKeys[$j]];
    		print "       - vs ".$compare['startip']."-".$compare['endip']."\n";

    		if( $compare['start'] > $current['end']+1 )
    			break;

    		$current['end'] = $compare['end'];
    		$current['endip'] = $compare['endip'];

    		print "             MERGED ->".$current['startip']."-".$current['endip']." \n";

    		unset($inclMappting[$mapKeys[$j]]);

    		$i++;
    	}
    }


    //
    // Merge overlapping or joint Excl entries
    //
    print "\n   * Merging overlapping Excl entries\n";
    $mapKeys = array_keys($exclMapping);
    $mapCount = count($exclMapping);
    for( $i=0; $i<$mapCount; $i++)
    {
    	$current = &$exclMapping[$mapKeys[$i]];
    	print "     - handling ".$current['startip']."-".$current['endip']."\n";
    	for( $j=$i+1; $j<$mapCount; $j++)
    	{
    		$compare = &$exclMapping[$mapKeys[$j]];
    		print "       - vs ".$compare['startip']."-".$compare['endip']."\n";

    		if( $compare['start'] > $current['end'] + 1 )
    			break;

    		$current['end'] = $compare['end'];
    		$current['endip'] = $compare['endip'];

    		print "             MERGED ->".$current['startip']."-".$current['endip']." \n";

    		unset($exclMapping[$mapKeys[$j]]);

    		$i++;
    	}
    }


    //
    // Now starts the REAL JOB : calculate IP RANGE HOLES !!!
    //
	print "\n   ** IP RANGE HOLES CALCULATION NOW !!! **\n";
    foreach( $inclMapping as $index => &$incl )
    {
    	$current = &$incl;
    	print "     - processing incl entry".$incl['startip']."-".$incl['endip']."\n";
    	foreach( $exclMapping as &$excl)
    	{
    		if( $excl['start'] > $current['end'] )
    			continue;
    		if( $excl['start'] < $current['start'] && $excl['end'] < $current['start'] )
    			continue;

    		print "        - vs ".$excl['startip']."-".$excl['endip'].": ";

    		// if this excl object is including ALL
    		if( $excl['start'] <= $current['start'] && $excl['end'] >= $current['end'] )
    		{
    			print "FULL  -> discarded\n";
    			unset($inclMapping[$index]);
    			break;
    		}
    		elseif( $excl['start'] <= $current['start'] && $excl['end'] <= $current['end'] )
    		{
    			$current['start'] = $excl['end'];
    			$current['startip'] = $excl['endip'];
    			print "LOWER COMPOUND";
    		}
    		elseif( $excl['start'] > $current['start'] && $excl['end'] >= $current['end'] )
    		{
    			$current['end'] = $excl['start'] -1;
    			$current['endip'] = long2ip($current['end']);
    			print "UPPER COMPOUND ";
    			break;
    		}
    		elseif( $excl['start'] > $current['start'] && $excl['end'] < $current['end'] )
    		{
    			print "MIDDLE COMPOUND";
    			$oldEnd = $current['end'];
    			$oldEndIP = $current['endip'];
    			$current['end'] = $excl['start']-1;
    			$current['endip'] =long2ip($current['end']);
    			unset($current);

    			$current = Array();
    			$inclMapping[] = &$current;
    			$current['start'] = $excl['end']+1;
    			$current['startip'] = long2ip($current['start']);
    			$current['end'] = $oldEnd;
    			$current['endip'] = $oldEndIP;
    		}
    		else
    		{
    			derr("\nUnsupported\n");
    		}


    		print "  : ".$current['startip']."-".$current['endip']."\n";
    	}
    }

    //
    // Clean original group and add objects that were not touched by exclusion groups
    // 
    $groupToProcess->removeAll();
    foreach( $inclNo as &$incl )
    {
    	$groupToProcess->add($incl['object'],false);
    }

    //
    // Sort incl objects IP mappings by Start IP
    //
    print "\n   * Sorting incl obj by StartIP again before creating final objects\n";
    $finalInclMapping = Array();
    $tmp = Array();
    foreach($inclMapping as &$incl)
    {
    	$tmp[] = $incl['start'];
    }
    unset($incl);
    sort($tmp, SORT_NUMERIC);
    foreach($tmp as $value)
    {
    	foreach($inclMapping as &$incl)
    	{
    		if( $value == $incl['start'] )
    		{
    			$oValue = $incl['startip']."-".$incl['endip'];
    			$oName = 'R-'.$incl['startip']."-".$incl['endip'];

    			print "     - (".$incl['startip']."-".$incl['endip']."): ";
    			$finalInclMapping[] = $incl;

    			$newO = null;
    			$newOcounter = 0;
    			while( $newO === null)
    			{
    				$newOName = $oName;
    				if( $newOcounter > 0 )
    					$newOName .= '-'.$newOcounter;

    				$newO = $store->find($newOName);

    				if( $newO !== null )
    				{
    					if( $newO->value() == $oValue )
    						break;
    					else
    						$newO = null;
    				}
    				else
    				{
    					$newO = $store->newAddress($newOName, 'ip-range', $oValue, '');
    					if( $newO === null )
    						derr('object creation error ???');
    				}

    				$newOcounter++;
    			}

    			print " --> ".$newO->name()."\n";
    			$groupToProcess->add($newO,false);
    		}
    	}
    }
    unset($incl);
    $groupToProcess->rewriteXML();
    $store->rewriteAddressStoreXML();

    print "\n  ** Total Ranges dynamically needed for group '".$groupToProcess->name()."' : ".count($finalInclMapping)."\n";


    print "\n*    done    *\n\n";
}



$pan->save_to_file($outputFile);


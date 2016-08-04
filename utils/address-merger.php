<?php
/*
 * Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

print "\n***********************************************\n";
print   "*********** ADDRESS-MERGER UTILITY **************\n\n";

set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml out=outputfile.xml location=shared|vsys1|dg1 ".
        "\n";

    if( !$shortMessage )
    {
        print PH::boldText("\nListing available arguments\n\n");

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            print " - ".PH::boldText($arg['niceName']);
            if( isset( $arg['argDesc']))
                print '='.$arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']))
                print "\n     ".$arg['shortHelp'];
            print "\n\n";
        }

        print "\n\n";
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit(true);
}


$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');


// load PAN-Configurator library
require_once("lib/panconfigurator.php");

PH::processCliArgs();

if( !isset(PH::$args['out']) )
    display_error_usage_exit(' "out=" argument is missing');
if( !isset(PH::$args['in']) )
    display_error_usage_exit(' "in=" argument is missing');

if( !isset(PH::$args['location']) )
    display_error_usage_exit(' "location=" argument is missing');

$origfile = PH::$args['in'];
$outputfile = PH::$args['out'];
$location = PH::$args['location'];

if( !file_exists($origfile) )
{
    derr("input file '$origfile' does not exists");
}

// destroy destination file if it exists
if( file_exists($outputfile) && is_file($outputfile) )
    unlink($outputfile);

echo " - loading configuration file '{$origfile}' ... ";
$panc = PH::getPanObjectFromConf($origfile);
echo "OK!\n";

if( $location == 'shared' )
{
    $store = $panc->addressStore;
}
else
{
    $findLocation = $panc->findSubSystemByName($location);
    if( $findLocation === null )
        derr("cannot find DeviceGroup/VSYS named '{$location}', check case or syntax");

    $store = $findLocation->addressStore;
}

if( $panc->isPanorama() )
{
    if( $location == 'shared' )
        $childDeviceGroups = $panc->deviceGroups;
    else
        $childDeviceGroups = $findLocation->childDeviceGroups(true);
}

echo " - location '{$location}' found\n";
echo " - found {$store->count()} address Objects\n";
echo " - computing address values database ... ";

//
// Building a hash table of all address objects with same value
//
$hashMap = Array();
foreach( $store->addressObjects() as $object )
{
    $skipThisOne = false;

    // Object with descandants in lower device groups should be excluded
    if( $panc->isPanorama() )
    {
        foreach( $childDeviceGroups as $dg )
        {
            if( $dg->addressStore->find($object->name(), null, FALSE) !== null )
            {
                $skipThisOne = true;
                break;
            }
        }
        if( $skipThisOne )
            continue;
    }

    $value = $object->value();

    // if object is /32, let's remove it to match equivalent non /32 syntax
    if( $object->isType_ipNetmask() && strpos($object->value() , '/32') !== false )
        $value = substr($value, 0, strlen($value) - 3);

    $value = $object->type().'-'.$value;
    $hashMap[$value][] = $object;
}

//
// Hashes with single entries have no duplicate, let's remove them
//
$countConcernedObjects = 0;
foreach( $hashMap as $index => &$hash )
{
    if( count($hash) == 1 )
        unset($hashMap[$index]);
    else
        $countConcernedObjects += count($hash);
}
unset($hash);
echo "OK!\n";

echo " - found ".count($hashMap)." duplicates values totalling {$countConcernedObjects} address objects which are duplicate\n";

echo "\n\nNow going after each duplicates for a replacement\n";

$countRemoved = 0;
foreach( $hashMap as $index => &$hash )
{
    $first = null;
    print " - value '{$index}'\n";
    foreach( $hash as $object)
    {
        /** @var Address $object */
        if( $first === null )
        {
            print "   * keeping object '{$object->name()}'\n";
            $first = $object;
        }
        else
        {
            print "    - replacing '{$object->name()}'\n";
            $object->replaceMeGlobally($first);
            $object->owner->remove($object);
            $countRemoved++;
        }
    }
}

echo "\n\nDuplicates removal is now done. Number of objects after cleanup: '{$store->countAddresses()}' (removed {$countConcernedObjects} services)\n\n";

print "\n\n***********************************************\n\n";

print "\n\n";
$panc->save_to_file($outputfile);

print "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";




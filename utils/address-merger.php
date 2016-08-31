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

echo "\n***********************************************\n";
echo   "*********** ADDRESS-MERGER UTILITY **************\n\n";

set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    echo PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml out=outputfile.xml location=shared|vsys1|dg1 ".
        "\n";

    if( !$shortMessage )
    {
        echo PH::boldText("\nListing available arguments\n\n");

        global $supportedArguments;

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            echo " - ".PH::boldText($arg['niceName']);
            if( isset( $arg['argDesc']))
                echo '='.$arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']))
                echo "\n     ".$arg['shortHelp'];
            echo "\n\n";
        }

        echo "\n\n";
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
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => '=vsys1|shared|dg1');
$supportedArguments['pickfilter'] =Array('niceName' => 'pickFilter', 'shortHelp' => 'specify a filter a pick which object will be kept while others will be replaced by this one', 'argDesc' => '=(name regex /^g/)');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

// load PAN-Configurator library
require_once("lib/panconfigurator.php");

PH::processCliArgs();

// check that only supported arguments were provided
foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        if( strpos($index,'subquery') === 0 )
        {
            $nestedQueries[$index] = &$arg;
            continue;
        }
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


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

$query = null;
if( isset(PH::$args['pickfilter']) )
{
    $query = new RQuery('address');
    $errMsg = '';
    if( $query->parseFromString(PH::$args['pickfilter'], $errMsg) === FALSE )
        derr("invalid pickFilter was input: ".$errMsg);
    echo " - pickFilter was input: ";
    $query->display();
    echo "\n";

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

    // Object with descendants in lower device groups should be excluded
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
    echo "\n";
    echo " - value '{$index}'\n";

    $pickedObject = null;

    if( $query !== null )
    {
        foreach( $hash as $object)
        {
            if( $query->matchSingleObject($object) )
            {
                $pickedObject = $object;
                break;
            }
        }
    }

    if( $pickedObject === null )
        $pickedObject = reset($hash);

    echo "   * keeping object '{$pickedObject->name()}'\n";

    foreach( $hash as $object)
    {
        if( $object === $pickedObject )
            continue;

        /** @var Address $object */
        echo "    - replacing '{$object->name()}'\n";
        $object->replaceMeGlobally($pickedObject);
        $object->owner->remove($object);
        $countRemoved++;
    }
}

echo "\n\nDuplicates removal is now done. Number of objects after cleanup: '{$store->countAddresses()}' (removed {$countRemoved} addresses)\n\n";

echo "\n\n***********************************************\n\n";

echo "\n\n";
$panc->save_to_file($outputfile);

echo "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";




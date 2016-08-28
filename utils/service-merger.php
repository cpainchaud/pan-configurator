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
echo   "*********** SERVICE-MERGER UTILITY **************\n\n";

set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    echo PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml out=outputfile.xml location=shared|vsys1|dg1 [dupAlgorithm=XYZ] [MergeCountLimit=100]".
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
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['dupalgorithm'] = Array('niceName' => 'DupAlgorithm', 'shortHelp' => 'specifies how to detect duplicates by port or by location where objects are used', 'argDesc'=> '=ports|WhereUsed');
$supportedArguments['mergecountlimit'] = Array('niceName' => 'mergecountlimit', 'shortHelp' => 'stop operations after X objects have been merged', 'argDesc'=> '=100');
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

if( isset(PH::$args['mergecountlimit']) )
    $mergeCountLimit = PH::$args['mergecountlimit'];
else
    $mergeCountLimit = false;

if( isset(PH::$args['dupalgorithm']) )
{
    $dupAlg = strtolower(PH::$args['dupalgorithm']);
    if( $dupAlg != 'ports' && $dupAlg != 'whereused')
        display_error_usage_exit('unsupported value for dupAlgorithm: '.PH::$args['dupalgorithm']);
}
else
    $dupAlg = 'ports';

$origfile = PH::$args['in'];
$outputfile = PH::$args['out'];
$location = PH::$args['location'];

if( !file_exists($origfile) )
{
    derr("input file '$origfile' does not exists");
}

// destroy destination file if it exists
if( file_exists($outputfile) && is_file($outputfile)  )
    unlink($outputfile);

echo " - loading configuration file '{$origfile}' ... ";
$panc = PH::getPanObjectFromConf($origfile);
echo "OK!\n";

if( $location == 'shared' )
{
    $store = $panc->serviceStore;
}
else
{
    $findLocation = $panc->findSubSystemByName($location);
    if( $findLocation === null )
        derr("cannot find DeviceGroup/VSYS named '{$location}', check case or syntax");

    $store = $findLocation->serviceStore;

}

echo " - location '{$location}' found\n";
echo " - found {$store->countServices()} services\n";
echo " - computing service values database ... ";

//
// Building a hash table of all service based on their REAL port mapping
//
$hashMap = Array();
if( $dupAlg == 'ports' )
    foreach( $store->serviceObjects() as $service )
    {
        $value = $service->dstPortMapping()->mappingToText();
        $hashMap[$value][] = $service;
    }
elseif( $dupAlg == 'whereused' )
    foreach( $store->serviceObjects() as $service )
    {
        $value = $service->getRefHashComp().$service->protocol();
        $hashMap[$value][] = $service;
    }
else derr("unsupported use case");

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

echo " - found ".count($hashMap)." duplicates values totalling {$countConcernedObjects} service objects which are duplicate\n";

echo "\n\nNow going after each duplicates for a replacement\n";

$countRemoved = 0;
if( $dupAlg == 'ports' )
    foreach( $hashMap as $index => &$hash )
    {
        $first = null;
        echo " - value '{$index}'\n";
        foreach($hash as $service)
        {
            /** @var Service $service */
            /** @var Service $first */
            if( $first === null )
            {
                echo "   * keeping service '{$service->name()}'\n";
                $first = $service;
            }
            else
            {
                echo "    - replacing '{$service->name()}'\n";
                $service->replaceMeGlobally($first);
                $service->owner->remove($service);
                $countRemoved++;
            }
            if( $mergeCountLimit !== FALSE && $countRemoved >= $mergeCountLimit )
            {
                echo "\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACH mergeCountLimit ({$mergeCountLimit})\n";
                break 2;
            }
        }
        echo "\n";
    }
elseif( $dupAlg == 'whereused' )
    foreach( $hashMap as $index => &$hash )
    {
        $first = null;
        echo " - group of ".count($hash)." services :\n";
        foreach($hash as $service)
        {
            /** @var Service $service */
            /** @var Service $first */
            if( $first === null )
            {
                $newName = $service->owner->findAvailableName('super-service');
                echo "   * keeping service '{$service->name()}' and renaming to '{$newName}''\n";
                $service->setName($newName);
                $first = $service;
            }
            else
            {
                $localMapping = $service->dstPortMapping();
                echo "    - adding the following ports to first service: ".$localMapping->mappingToText()."\n";
                $localMapping->mergeWithMapping($first->dstPortMapping());
                if( $first->isTcp() )
                    $first->setDestPort($localMapping->tcpMappingToText());
                else
                    $first->setDestPort($localMapping->udpMappingToText());


                echo "    - removing '{$service->name()}' from places where it's used:\n";
                $service->removeWhereIamUsed(true, 7);
                $service->owner->remove($service);
                $countRemoved++;
            }
            if( $mergeCountLimit !== FALSE && $countRemoved >= $mergeCountLimit )
            {
                echo "\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACH mergeCountLimit ({$mergeCountLimit})\n";
                break 2;
            }

        }
        echo "   *- final mapping for service '{$first->name()}': {$first->getDestPort()}\n";
        
        echo "\n";
    }
else derr("unsupported use case");


echo "\n\nDuplicates removal is now done. Number is services after cleanup: '{$store->countServices()}' (removed {$countRemoved} services)\n\n";

echo "\n\n***********************************************\n\n";

echo "\n\n";
$panc->save_to_file($outputfile);

echo "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";




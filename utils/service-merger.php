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
print   "*********** SERVICE-MERGER UTILITY **************\n\n";

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
    derr(' "out=" argument is missing');
if( !isset(PH::$args['in']) )
    derr(' "in=" argument is missing');

if( !isset(PH::$args['location']) )
    derr(' "location=" argument is missing');

$origfile = PH::$args['in'];
$outputfile = PH::$args['out'];
$location = PH::$args['location'];

if( !file_exists($origfile) )
{
    derr("input file '$origfile' does not exists");
}

// destroy destination file if it exists
if( file_exists($outputfile) )
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

$hashMap = Array();

foreach( $store->serviceObjects() as $service )
{
    $value = $service->dstPortMapping()->mappingToText();
    $hashMap[$value][] = $service;
}
$countConcernedObjects = 0;
foreach( $hashMap as $index => &$hash )
{
    if( count($hash) == 1 )
        unset($hashMap[$index]);
    else
        $countConcernedObjects += count($hash);
}
unset($hash);
echo "OK\n!";

echo " - found ".count($hashMap)." duplicates values totalling {$countConcernedObjects} service objects which are duplicate\n";

echo "\n\nNow going after each duplicates for a replacement\n";

$countRemoved = 0;
foreach( $hashMap as $index => &$hash )
{
    $first = null;
    print " - value '{$index}'\n";
    foreach($hash as $service)
    {
        /** @var Service $service */
        if( $first === null )
        {
            print "   * keeping service '{$service->name()}'\n";
            $first = $service;
        }
        else
        {
            print "    - replacing '{$service->name()}'\n";
            $service->replaceMeGlobally($first);
            $service->owner->remove($service);
            $countRemoved++;
        }
    }
}

echo "\n\nDuplicates removal is now done. Number is services after cleanup: '{$store->countServices()}' (removed {$countConcernedObjects} services)\n\n";

print "\n\n***********************************************\n\n";

print "\n\n";
$panc->save_to_file($outputfile);

print "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";




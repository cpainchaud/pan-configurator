<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
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
echo   "*********** ".basename(__FILE__)." UTILITY **************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");
require_once(dirname(__FILE__).'/common/misc.php');



$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'delete', 'shortHelp' => 'Clears API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = Array('niceName' => 'add', 'shortHelp' => 'Adds API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = Array('niceName' => 'test', 'shortHelp' => 'Tests API key for hostname/IP provided as an argument.', 'argDesc' => '[hostname or IP]');
$supportedArguments[] = Array('niceName' => 'apikey', 'shortHelp' => 'can be used in combination with add argument to use specific API key provided as an argument.', 'argDesc' => '[API Key]');
$supportedArguments[] = Array('niceName' => 'hiddenpw', 'shortHelp' => 'Use this if the entered password should not be displayed.');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." [delete=hostOrIP] [add=hostOrIP] [test=hostOrIP] [hiddenPW]";

prepareSupportedArgumentsArray($supportedArguments);
PH::processCliArgs();

// check that only supported arguments were provided
foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

echo " - loading keystore from file in user home directory... ";
PanAPIConnector::loadConnectorsFromUserHome();
echo "OK!\n";

echo "\n";

$noArgProvided = true;

if( isset(PH::$args['hiddenpw']) )
    $hiddenPW = TRUE;
else
    $hiddenPW = FALSE;

if( isset(PH::$args['delete']) )
{
    $noArgProvided = false;
    $deleteHost = PH::$args['delete'];
    echo " - requested to delete Host/IP '{$deleteHost}'\n";
    if( !is_string($deleteHost) )
        derr("argument of 'delete' must be a string , wrong input provided");

    $foundConnector = false;
    foreach(PanAPIConnector::$savedConnectors as $cIndex => $connector)
    {
        if( $connector->apihost == $deleteHost )
        {
            $foundConnector = true;
            echo " - found and deleted\n\n";
            unset(PanAPIConnector::$savedConnectors[$cIndex]);
            PanAPIConnector::saveConnectorsToUserHome();
        }
    }
    if( !$foundConnector )
        echo "\n\n **WARNING** no host or IP named '{$deleteHost}' was found so it could not be deleted\n\n";
}

if( isset(PH::$args['add']) )
{
    $noArgProvided = false;
    $addHost = PH::$args['add'];
    echo " - requested to add Host/IP '{$addHost}'\n";

    if( !isset(PH::$args['apikey']) )
        PanAPIConnector::findOrCreateConnectorFromHost( $addHost, null, TRUE, TRUE, $hiddenPW);
    else
        PanAPIConnector::findOrCreateConnectorFromHost( $addHost, PH::$args['apikey'] );
}

if( isset(PH::$args['test']) )
{
    $noArgProvided = false;
    $checkHost = PH::$args['test'];

    if( $checkHost == 'any' || $checkHost == 'all')
    {
        foreach(PanAPIConnector::$savedConnectors as $connector)
        {
            $checkHost = $connector->apihost;
            echo " - requested to test Host/IP '{$checkHost}'\n";

            PH::enableExceptionSupport();
            try
            {
                if( !isset(PH::$args['apikey']) )
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost( $checkHost, null, TRUE, TRUE, $hiddenPW);
                else
                    $connector = PanAPIConnector::findOrCreateConnectorFromHost( $checkHost, PH::$args['apikey'] );

                $connector->testConnectivity();
            }
            catch(Exception $e)
            {
                PH::disableExceptionSupport();
                print "   ***** API Error occured : ".$e->getMessage()."\n\n";
            }

            PH::disableExceptionSupport();
            print "\n";
        }
    }
    else
    {
        echo " - requested to test Host/IP '{$checkHost}'\n";
        if( !isset(PH::$args['apikey']) )
            $connector = PanAPIConnector::findOrCreateConnectorFromHost( $checkHost, null, TRUE, TRUE, $hiddenPW);
        else
            $connector = PanAPIConnector::findOrCreateConnectorFromHost( $checkHost, PH::$args['apikey'] );

        $connector->testConnectivity();

        print "\n";
    }
}

$keyCount = count(PanAPIConnector::$savedConnectors);
echo "Listing available keys:\n";

$connectorList = Array();
foreach(PanAPIConnector::$savedConnectors as $connector)
{
    $connectorList[$connector->apihost] = $connector;
}
ksort($connectorList);

foreach($connectorList as $connector)
{
    $key = $connector->apikey;
    if( strlen($key) > 24 )
        $key = substr($key, 0, 12).'...'.substr($key, strlen($key)-12);
    $host = str_pad($connector->apihost, 15, ' ', STR_PAD_RIGHT);

    echo " - Host {$host}: key={$key}\n";
}

if( $noArgProvided )
{
    print "\n";
    display_usage_and_exit();
}

echo "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";




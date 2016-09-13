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
echo   "*********** ".basename(__FILE__)." UTILITY **************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");
require_once(dirname(__FILE__).'/common/misc.php');

$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => 'sub1[,sub2]');
$supportedArguments[] = Array(    'niceName' => 'DupAlgorithm',
                                                'shortHelp' => "Specifies how to detect duplicates:\n".
                                                    "  - SamePorts: objects with same ports will be replaced by the one picked (default)\n".
                                                    "  - WhereUsed: objects used exactly in the same location will be merged into 1 single object and all ports covered by these objects will be aggregated\n",
                                                'argDesc'=> 'SamePorts|WhereUsed');
$supportedArguments[] = Array('niceName' => 'mergecountlimit', 'shortHelp' => 'stop operations after X objects have been merged', 'argDesc'=> '100');
$supportedArguments[] = Array(  'niceName' => 'pickFilter',
                                            'shortHelp' => "specify a filter a pick which object will be kept while others will be replaced by this one.\n".
                                                "   ie: 2 services are found to be mergeable: 'H-1.1.1.1' and 'Server-ABC'. Then by using pickFilter=(name regex /^H-/) you would ensure that object H-1.1.1.1 would remain and Server-ABC be replaced by it.",
                                            'argDesc' => '(name regex /^g/)');
$supportedArguments[] = Array('niceName' => 'allowMergingWithUpperLevel', 'shortHelp' => 'when this argument is specified, it instructs the script to also look for duplicates in upper level');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');

$usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml [out=outputfile.xml] location=shared [dupAlgorithm=XYZ] [MergeCountLimit=100] ['pickFilter=(name regex /^H-/)']...";

prepareSupportedArgumentsArray($supportedArguments);

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
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


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
    if( $dupAlg != 'sameports' && $dupAlg != 'whereused')
        display_error_usage_exit('unsupported value for dupAlgorithm: '.PH::$args['dupalgorithm']);
}
else
    $dupAlg = 'sameports';

$location = PH::$args['location'];

//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod(PH::$args['in'], true);
$xmlDoc = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if( $configInput['type'] == 'file' )
{
    $apiMode = false;
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc = new DOMDocument();
    echo " - Reading XML file from disk... ";
    if( ! $xmlDoc->load($configInput['filename']) )
        derr("error while reading xml config file");
    echo "OK!\n";

}
elseif ( $configInput['type'] == 'api'  )
{
    $apiMode = true;
    echo " - Downloading config from API... ";
    $xmlDoc = $configInput['connector']->getCandidateConfig();
    echo "OK!\n";
}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult = DH::findXPath('/config/devices/entry/vsys', $xmlDoc);
if( $xpathResult === FALSE )
    derr('XPath error happened');
if( $xpathResult->length <1 )
    $configType = 'panorama';
else
    $configType = 'panos';
unset($xpathResult);


if( $configType == 'panos' )
    $panc = new PANConf();
else
    $panc = new PanoramaConf();

echo " - Detected platform type is '{$configType}'\n";

if( $configInput['type'] == 'api' )
    $panc->connector = $configInput['connector'];

//
// load the config
//
echo " - Loading configuration through PAN-Configurator library... ";
$loadStartMem = memory_get_usage(true);
$loadStartTime = microtime(true);
$panc->load_from_domxml($xmlDoc);
$loadEndTime = microtime(true);
$loadEndMem = memory_get_usage(true);
$loadElapsedTime = number_format( ($loadEndTime - $loadStartTime), 2, '.', '');
$loadUsedMem = convert($loadEndMem - $loadStartMem);
echo "OK! ($loadElapsedTime seconds, $loadUsedMem memory)\n";
// --------------------

// </editor-fold>


if( !$apiMode )
{
    if( !isset(PH::$args['out']) )
        display_error_usage_exit(' "out=" argument is missing');

    $outputfile = PH::$args['out'];

    // destroy destination file if it exists
    if( file_exists($outputfile) && is_file($outputfile) )
        unlink($outputfile);
}

if( $location == 'shared' )
{
    $store = $panc->serviceStore;
    $parentStore = null;
}
else
{
    $findLocation = $panc->findSubSystemByName($location);
    if( $findLocation === null )
        derr("cannot find DeviceGroup/VSYS named '{$location}', check case or syntax");

    $store = $findLocation->serviceStore;
    $parentStore = $findLocation->owner->serviceStore;

}

$query = null;
if( isset(PH::$args['pickfilter']) )
{
    $query = new RQuery('service');
    $errMsg = '';
    if( $query->parseFromString(PH::$args['pickfilter'], $errMsg) === FALSE )
        derr("invalid pickFilter was input: ".$errMsg);
    echo " - pickFilter was input: ";
    $query->display();
    echo "\n";

}

$upperLevelSearch = false;
if( isset(PH::$args['allowmergingwithupperlevel']) )
    $upperLevelSearch = true;

echo " - upper level search status : ".boolYesNo($upperLevelSearch)."\n";
echo " - location '{$location}' found\n";
echo " - found {$store->countServices()} services\n";
echo " - DupAlgorithm selected: {$dupAlg}\n";
echo " - computing address values database ... ";
sleep(1);


//
// Building a hash table of all service based on their REAL port mapping
//
if( $upperLevelSearch)
    $objectsToSearchThrough = $store->nestedPointOfView();
else
    $objectsToSearchThrough = $store->serviceObjects();

$hashMap = Array();
$upperHashMap = Array();
if( $dupAlg == 'sameports' )
    foreach( $objectsToSearchThrough as $object )
    {
        if( !$object->isService() )
            continue;
        if( $object->isTmpSrv() )
            continue;

        $value = $object->dstPortMapping()->mappingToText();

        if( $object->owner === $store )
        {
            $hashMap[$value][] = $object;
            if( $parentStore !== null )
            {
                $findAncestor = $parentStore->find($object->name(), null, true);
                if( $findAncestor !== null )
                    $object->ancestor = $findAncestor;
            }
        }
        else
            $upperHashMap[$value][] = $object;

    }
elseif( $dupAlg == 'whereused' )
    foreach( $objectsToSearchThrough as $object )
    {
        if( !$object->isService() )
            continue;
        if( $object->isTmpSrv() )
            continue;

        $value = $object->getRefHashComp().$object->protocol();
        if( $object->owner === $store )
        {
            $hashMap[$value][] = $object;
            if( $parentStore !== null )
            {
                $findAncestor = $parentStore->find($object->name(), null, true);
                if( $findAncestor !== null )
                    $object->ancestor = $findAncestor;
            }
        }
        else
            $upperHashMap[$value][] = $object;
    }
else derr("unsupported use case");

//
// Hashes with single entries have no duplicate, let's remove them
//
$countConcernedObjects = 0;
foreach( $hashMap as $index => &$hash )
{
    if( count($hash) == 1 && !isset($upperHashMap[$index]) && !isset(reset($hash)->ancestor) )
        unset($hashMap[$index]);
    else
        $countConcernedObjects += count($hash);
}
unset($hash);
echo "OK!\n";

echo " - found ".count($hashMap)." duplicates values totalling {$countConcernedObjects} service objects which are duplicate\n";

echo "\n\nNow going after each duplicates for a replacement\n";

$countRemoved = 0;
if( $dupAlg == 'sameports' )
    foreach( $hashMap as $index => &$hash )
    {
        echo "\n";
        echo " - value '{$index}'\n";

        $pickedObject = null;

        if( $query !== null )
        {
            if( isset($upperHashMap[$index]) )
            {
                foreach( $upperHashMap[$index] as $object )
                {
                    if( $query->matchSingleObject($object) )
                    {
                        $pickedObject = $object;
                        break;
                    }
                }
                if( $pickedObject === null )
                    $pickedObject = reset($upperHashMap[$index]);

                echo "   * using object from upper level : '{$pickedObject->name()}'\n";
            }
            else
            {
                foreach( $hash as $object )
                {
                    if( $query->matchSingleObject($object) )
                    {
                        $pickedObject = $object;
                        break;
                    }
                }
                if( $pickedObject === null )
                    $pickedObject = reset($hash);

                echo "   * keeping object '{$pickedObject->name()}'\n";
            }
        }
        else
        {
            if( isset($upperHashMap[$index]) )
            {
                $pickedObject = reset($upperHashMap[$index]);
                echo "   * using object from upper level : '{$pickedObject->name()}'\n";
            }
            else
            {
                $pickedObject = reset($hash);
                echo "   * keeping object '{$pickedObject->name()}'\n";
            }
        }

        foreach( $hash as $object)
        {
            /** @var Service $object */

            if( isset($object->ancestor) )
            {
                $ancestor = $object->ancestor;
                /** @var Service $ancestor */
                if( $upperLevelSearch && !$ancestor->isTmpSrv() && !$ancestor->isGroup() )
                {
                    if( $object->dstPortMapping()->equals($ancestor->dstPortMapping()) )
                    {
                        echo "    - object '{$object->name()}' merged with its ancestor, deleting this one... ";
                        $object->replaceMeGlobally($ancestor);
                        if( $apiMode )
                            $object->owner->API_remove($object);
                        else
                            $object->owner->remove($object);

                        echo "OK!\n";

                        if( $pickedObject === $object )
                            $pickedObject = $ancestor;

                        $countRemoved++;
                        continue;
                    }
                }
                echo "    - object '{$object->name()}' cannot be merged because it has an ancestor\n";
                continue;
            }

            if( $object === $pickedObject )
                continue;

            echo "    - replacing '{$object->name()}'\n";
            if( $apiMode )
            {
                $object->API_addObjectWhereIamUsed( $pickedObject, true, 6);
                $object->API_removeWhereIamUsed( true, 6);
                $object->owner->API_remove($object);
            }
            else
            {
                $object->addObjectWhereIamUsed( $pickedObject, true, 6);
                $object->removeWhereIamUsed( true, 6);
                $object->owner->remove($object);
            }
            $countRemoved++;

            if( $mergeCountLimit !== FALSE && $countRemoved >= $mergeCountLimit )
            {
                echo "\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACHED mergeCountLimit ({$mergeCountLimit})\n";
                break 2;
            }
        }
    }
elseif( $dupAlg == 'whereused' )
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
            /** @var Service $object */
            /** @var Service $object */

            if( isset($object->ancestor) )
            {
                $ancestor = $object->ancestor;
                /** @var Service $ancestor */
                echo "    - object '{$object->name()}' cannot be merged because it has an ancestor\n";
                continue;
            }

            if( $object === $pickedObject )
                continue;

            $localMapping = $object->dstPortMapping();
            echo "    - adding the following ports to first service: ".$localMapping->mappingToText()."\n";
            $localMapping->mergeWithMapping($pickedObject->dstPortMapping());
            if( $pickedObject->isTcp() )
                $pickedObject->setDestPort($localMapping->tcpMappingToText());
            else
                $pickedObject->setDestPort($localMapping->udpMappingToText());


            echo "    - removing '{$object->name()}' from places where it's used:\n";
            $object->removeWhereIamUsed(true, 7);
            $object->owner->remove($object);
            $countRemoved++;

            if( $mergeCountLimit !== FALSE && $countRemoved >= $mergeCountLimit )
            {
                echo "\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACH mergeCountLimit ({$mergeCountLimit})\n";
                break 2;
            }

        }
        echo "   *- final mapping for service '{$pickedObject->name()}': {$pickedObject->getDestPort()}\n";
        
        echo "\n";
    }
else derr("unsupported use case");


echo "\n\nDuplicates removal is now done. Number is services after cleanup: '{$store->countServices()}' (removed {$countRemoved} services)\n\n";

echo "\n\n***********************************************\n\n";

echo "\n\n";

if( !$apiMode )
    $panc->save_to_file($outputfile);

echo "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";




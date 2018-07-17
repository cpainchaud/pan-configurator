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
$supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments[] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'vsys1|shared|dg1');
$supportedArguments[] = Array(    'niceName' => 'DupAlgorithm',
    'shortHelp' => "Specifies how to detect duplicates:\n".
        "  - SameAddress: objects with same Network-Value will be replaced by the one picked (default)\n".
        "  - Identical: objects with same network-value and same name will be replaced by the one picked\n".
        "  - WhereUsed: objects used exactly in the same location will be merged into 1 single object and all ports covered by these objects will be aggregated\n",
    'argDesc'=> 'SameAddress | Identical | WhereUsed');
$supportedArguments[] = Array('niceName' => 'mergeCountLimit', 'shortHelp' => 'stop operations after X objects have been merged', 'argDesc'=> '100');
$supportedArguments[] = Array('niceName' => 'pickFilter', 'shortHelp' => 'specify a filter a pick which object will be kept while others will be replaced by this one', 'argDesc' => '(name regex /^g/)');
$supportedArguments[] = Array('niceName' => 'excludeFilter', 'shortHelp' => 'specify a filter to exclude objects from merging process entirely', 'argDesc' => '(name regex /^g/)');
$supportedArguments[] = Array('niceName' => 'allowMergingWithUpperLevel', 'shortHelp' => 'when this argument is specified, it instructs the script to also look for duplicates in upper level');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = Array('niceName' => 'exportCSV', 'shortHelp' => 'when this argument is specified, it instructs the script to print out the kept and removed objects per value');
$supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=inputfile.xml [out=outputfile.xml] location=shared ['pickFilter=(name regex /^H-/)']\n".
                        "       php ".basename(__FILE__)." in=api://192.169.50.10 location=shared ['pickFilter=(name regex /^H-/)']";

prepareSupportedArgumentsArray($supportedArguments);

PH::processCliArgs();

$nestedQueries = Array();
$deletedObjects = Array();
$debugAPI = false;

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

$location = PH::$args['location'];

if( isset(PH::$args['mergecountlimit']) )
    $mergeCountLimit = PH::$args['mergecountlimit'];
else
    $mergeCountLimit = false;

if( isset(PH::$args['dupalgorithm']) )
{
    $dupAlg = strtolower(PH::$args['dupalgorithm']);
    if( $dupAlg != 'sameaddress' && $dupAlg != 'whereused' && $dupAlg != 'identical')
        display_error_usage_exit('unsupported value for dupAlgorithm: '.PH::$args['dupalgorithm']);
}
else
    $dupAlg = 'sameaddress';

if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

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
    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
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
    $store = $panc->addressStore;
    $parentStore = null;
}
else
{
    $findLocation = $panc->findSubSystemByName($location);
    if( $findLocation === null )
        derr("cannot find DeviceGroup/VSYS named '{$location}', check case or syntax");

    $store = $findLocation->addressStore;
    $parentStore = $findLocation->owner->addressStore;
}

if( $panc->isPanorama() )
{
    if( $location == 'shared' )
        $childDeviceGroups = $panc->deviceGroups;
    else
        $childDeviceGroups = $findLocation->childDeviceGroups(true);
}

$pickFilter = null;
if( isset(PH::$args['pickfilter']) )
{
    $pickFilter = new RQuery('address');
    $errMsg = '';
    if( $pickFilter->parseFromString(PH::$args['pickfilter'], $errMsg) === FALSE )
        derr("invalid pickFilter was input: ".$errMsg);
    echo " - pickFilter was input: ";
    $pickFilter->display();
    echo "\n";

}
$excludeFilter = null;
if( isset(PH::$args['excludefilter']) )
{
    $excludeFilter = new RQuery('address');
    $errMsg = '';
    if( $excludeFilter->parseFromString(PH::$args['excludefilter'], $errMsg) === FALSE )
        derr("invalid pickFilter was input: ".$errMsg);
    echo " - excludeFilter was input: ";
    $excludeFilter->display();
    echo "\n";
}

$upperLevelSearch = false;
if( isset(PH::$args['allowmergingwithupperlevel']) )
    $upperLevelSearch = true;

echo " - upper level search status : ".boolYesNo($upperLevelSearch)."\n";
echo " - location '{$location}' found\n";
echo " - found {$store->countAddresses()} address Objects\n";
echo " - DupAlgorithm selected: {$dupAlg}\n";
echo " - computing address values database ... ";
sleep(1);

//
// Building a hash table of all address objects with same value
//
if( $upperLevelSearch)
    $objectsToSearchThrough = $store->nestedPointOfView();
else
    $objectsToSearchThrough = $store->addressObjects();

$hashMap = Array();
$upperHashMap = Array();
if( $dupAlg == 'sameaddress' || $dupAlg == 'identical' )
{
    foreach( $objectsToSearchThrough as $object )
    {
        if( !$object->isAddress() )
            continue;
        if( $object->isTmpAddr() )
            continue;

        if( $excludeFilter !== null && $excludeFilter->matchSingleObject(Array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
            continue;

        $skipThisOne = FALSE;

        // Object with descendants in lower device groups should be excluded
        if( $panc->isPanorama() && $object->owner === $store )
        {
            foreach( $childDeviceGroups as $dg )
            {
                if( $dg->addressStore->find($object->name(), null, FALSE) !== null )
                {
                    print "\n- object '".$object->name()."'' skipped because of same object name available at lower level\n";
                    $skipThisOne = TRUE;
                    break;
                }
            }
            if( $skipThisOne )
                continue;
        }

        $value = $object->value();

        // if object is /32, let's remove it to match equivalent non /32 syntax
        if( $object->isType_ipNetmask() && strpos($object->value(), '/32') !== FALSE )
            $value = substr($value, 0, strlen($value) - 3);

        $value = $object->type() . '-' . $value;

        if( $object->owner === $store )
        {
            $hashMap[$value][] = $object;
            if( $parentStore !== null )
            {
                $findAncestor = $parentStore->find($object->name(), null, TRUE);
                if( $findAncestor !== null )
                    $object->ancestor = $findAncestor;
            }
        }
        else
            $upperHashMap[$value][] = $object;
    }
}
elseif( $dupAlg == 'whereused' )
    foreach( $objectsToSearchThrough as $object )
    {
        if( !$object->isAddress() )
            continue;
        if( $object->isTmpAddr() )
            continue;

        if( $object->countReferences() == 0 )
            continue;

        if( $excludeFilter !== null && $excludeFilter->matchSingleObject(Array('object' =>$object, 'nestedQueries'=>&$nestedQueries)) )
            continue;

        $value = $object->getRefHashComp().$object->getNetworkValue();
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

echo " - found ".count($hashMap)." duplicates values totalling {$countConcernedObjects} address objects which are duplicate\n";

echo "\n\nNow going after each duplicates for a replacement\n";

$countRemoved = 0;
foreach( $hashMap as $index => &$hash )
{
    echo "\n";
    echo " - value '{$index}'\n";
    $deletedObjects[$index]['removed'] = "";

    $pickedObject = null;

    if( $pickFilter !== null )
    {
        if( isset($upperHashMap[$index]) )
        {
            foreach( $upperHashMap[$index] as $object )
            {
                if( $pickFilter->matchSingleObject( Array('object' =>$object, 'nestedQueries'=>&$nestedQueries) ) )
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
                if( $pickFilter->matchSingleObject( Array('object' =>$object, 'nestedQueries'=>&$nestedQueries) ) )
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


    // Merging loop finally!
    foreach( $hash as $objectIndex => $object)
    {
        /** @var Address $object */
        if( isset($object->ancestor) )
        {
            $ancestor = $object->ancestor;
            $ancestor_different_value = "";

            if( !$ancestor->isAddress() )
            {
                echo "    - SKIP: object name '{$object->name()}' as one ancestor is of type addressgroup\n";
                continue;
            }

            /** @var Address $ancestor */
            if( $upperLevelSearch && !$ancestor->isGroup() && !$ancestor->isTmpAddr() && ($ancestor->isType_ipNetmask()||$ancestor->isType_ipRange()||$ancestor->isType_FQDN()) )
            {
                if( $object->getIP4Mapping()->equals($ancestor->getIP4Mapping()) )
                {
                    if( $dupAlg == 'identical' )
                        if( $pickedObject->name() != $ancestor->name() )
                        {
                            echo "    - SKIP: object name '{$object->name()}' is not IDENTICAL to object name from upperlevel '{$pickedObject->name()}'\n";
                            continue;
                        }

                    echo "    - object '{$object->name()}' merged with its ancestor, deleting this one... ";
                    $deletedObjects[$index]['kept'] = $pickedObject->name();
                    if( $deletedObjects[$index]['removed'] == "")
                        $deletedObjects[$index]['removed'] = $object->name();
                    else
                        $deletedObjects[$index]['removed'] .= "|".$object->name();
                    $object->replaceMeGlobally($ancestor);
                    if( $apiMode )
                        $object->owner->API_remove($object);
                    else
                        $object->owner->remove($object);

                    echo "OK!\n";

                    echo "         anchestor name: '{$ancestor->name()}' DG: ";
                    if( $ancestor->owner->owner->name() == "" ) print "'shared'";
                    else print "'{$ancestor->owner->owner->name()}'";
                    print  "  value: '{$ancestor->value()}' \n";

                    if( $pickedObject === $object )
                        $pickedObject = $ancestor;

                    $countRemoved++;

                    if( $mergeCountLimit !== FALSE && $countRemoved >= $mergeCountLimit )
                    {
                        echo "\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACHED mergeCountLimit ({$mergeCountLimit})\n";
                        break 2;
                    }

                    continue;
                }
                else
                    $ancestor_different_value = "with different value";


            }
            echo "    - object '{$object->name()}' '{$ancestor->type()}' cannot be merged because it has an ancestor ".$ancestor_different_value."\n";

            echo "         anchestor name: '{$ancestor->name()}' DG: ";
            if( $ancestor->owner->owner->name() == "" ) print "'shared'";
            else print "'{$ancestor->owner->owner->name()}'";
            print  "  value: '{$ancestor->value()}' \n";

            continue;
        }

        if( $object === $pickedObject )
            continue;

        if( $dupAlg != 'identical' )
        {
            echo "    - replacing '{$object->_PANC_shortName()}' ...\n";
            $object->__replaceWhereIamUsed($apiMode, $pickedObject, TRUE, 5);

            echo "    - deleting '{$object->_PANC_shortName()}'\n";
            $deletedObjects[$index]['kept'] = $pickedObject->name();
            if( $deletedObjects[$index]['removed'] == "")
                $deletedObjects[$index]['removed'] = $object->name();
            else
                $deletedObjects[$index]['removed'] .= "|".$object->name();
            if( $apiMode )
            {
                $object->owner->API_remove($object);
            }
            else
            {
                $object->owner->remove($object);
            }

            $countRemoved++;

            if( $mergeCountLimit !== FALSE && $countRemoved >= $mergeCountLimit )
            {
                echo "\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACHED mergeCountLimit ({$mergeCountLimit})\n";
                break 2;
            }
        }
        else
            echo "    - SKIP: object name '{$object->name()}' is not IDENTICAL\n";
    }
}

echo "\n\nDuplicates removal is now done. Number of objects after cleanup: '{$store->countAddresses()}' (removed {$countRemoved} addresses)\n\n";

echo "\n\n***********************************************\n\n";

echo "\n\n";

if( !$apiMode )
    $panc->save_to_file($outputfile);


if( isset(PH::$args['exportcsv']) )
{
    foreach( $deletedObjects as $obj_index => $object_name )
    {
        print $obj_index.",".$object_name['kept'].",".$object_name['removed']."\n";
    }
}


echo "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";




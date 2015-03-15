<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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
print   "*********** SERVICE-EDIT UTILITY **************\n\n";


set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." type=panos|panorama in=inputfile.xml out=outputfile.xml location=all|shared|sub ".
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";
    print "php ".basename(__FILE__)." listactions   : list supported actions\n";
    print "php ".basename(__FILE__)." listfilters   : list supported filter\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";
    print PH::boldText("\nExamples:\n");
    print " - php ".basename(__FILE__)." type=panorama in=api://192.169.50.10 location=DMZ-Firewall-Group actions=displayReferences 'filter=(name eq Mail-Host1)'\n";
    print " - php ".basename(__FILE__)." type=panos in=config.xml out=output.xml location=any actions=delete\n";

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

print "\n";

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = false;
$objectsLocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['listactions'] = Array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
$supportedArguments['listfilters'] = Array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
$supportedArguments['stats'] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
$supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters objects based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator [value])');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');


$supportedActions = Array();
// <editor-fold desc="  ****  Supported Actions Array  ****" defaultstate="collapsed" >




$supportedActions['delete'] = Array(
    'name' => 'delete',
    'file' => 'if( $object->countReferences() != 0)
                    derr("this object is used by other objects and cannot be deleted (use deleteForce to try anyway)");
                $object->owner->remove($object);',
    'api' => 'if( $object->countReferences() != 0)
                    derr("this object is used by other objects and cannot be deleted (use deleteForce to try anyway)");
                $object->owner->API_remove($object);',
    'args' => false,
);

$supportedActions['deleteforce'] = Array(
    'name' => 'deleteForce',
    'file' => '$object->owner->remove($object);',
    'api' => '$object->owner->API_remove($object);',
    'args' => false,
);

$supportedActions['replacebymembersanddelete'] = Array(
    'name' => 'replaceByMembersAndDelete',
    'file' => "\$objectRefs = \$object->getReferences();
                \$clearForAction = true;
                foreach( \$objectRefs as \$objectRef )
                {
                    \$class = get_class(\$objectRef);
                    if( \$class != 'ServiceRuleContainer' && \$class != 'ServiceGroup' )
                    {
                        \$clearForAction = false;
                        print \"     *  skipped because its used in unsupported class \$class\\n\";
                        break;
                    }
                }
                if( \$clearForAction )
                {
                    foreach( \$objectRefs as \$objectRef )
                    {
                        \$class = get_class(\$objectRef);
                        if( \$class == 'ServiceRuleContainer' || \$class == 'ServiceGroup')
                        {
                            foreach( \$object->members() as \$objectMember )
                            {
                                \$objectRef->add(\$objectMember);
                            }
                            \$objectRef->remove(\$object);
                        }
                        else
                        {
                            derr('unsupported class');
                        }

                    }
                    \$object->owner->remove(\$object);
                }",
    'api' => "\$objectRefs = \$object->getReferences();
                \$clearForAction = true;
                foreach( \$objectRefs as \$objectRef )
                {
                    \$class = get_class(\$objectRef);
                    if( \$class != 'ServiceRuleContainer' && \$class != 'ServiceGroup' )
                    {
                        \$clearForAction = false;
                        print \"     *  skipped because its used in unsupported class \$class\\n\";
                        break;
                    }
                }
                if( \$clearForAction )
                {
                    foreach( \$objectRefs as \$objectRef )
                    {
                        \$class = get_class(\$objectRef);
                        if( \$class == 'ServiceRuleContainer' || \$class == 'ServiceGroup')
                        {
                            foreach( \$object->members() as \$objectMember )
                            {
                                \$objectRef->API_add(\$objectMember);
                            }
                            \$objectRef->API_remove(\$object);
                        }
                        else
                        {
                            derr('unsupported class');
                        }
                    }
                    \$object->owner->API_remove(\$object);
                }",
    'args' => false,
);


$supportedActions['displayreferences'] = Array(
    'name' => 'displayReferences',
    'file' =>  "\$object->display_references(7);",
    'api' =>   "\$object->display_references(7);",
    'args' => false
);

$supportedActions['display'] = Array(
    'name' => 'display',
    'file' =>  "print \"     * \".get_class(\$object).\" '{\$object->name()}' \n\";
                if( \$object->isGroup() ) foreach(\$object->members() as \$member) print \"          - {\$member->name()}\n\";
                print \"\n\n\";",
    'api' =>  "print \"     * \".get_class(\$object).\" '{\$object->name()}' \n\";
                if( \$object->isGroup() ) foreach(\$object->members() as \$member) print \"          - {\$member->name()}\n\";
                print \"\n\n\";",
    'args' => false
);
// </editor-fold>



PH::processCliArgs();

foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


if( isset(PH::$args['listactions']) )
{
    ksort($supportedActions);

    print "Listing of supported actions:\n\n";

    print str_pad('', 100, '-')."\n";
    print str_pad('       Action name', 50, ' ')."| OFF | API |     comment\n";
    print str_pad('', 100, '-')."\n";

    foreach($supportedActions as &$action )
    {
        if( isset($action['api']) && $action['api'] != 'unsupported' )
            $apiSupport = 'yes';
        else
            $apiSupport = 'no ';

        if( isset($action['file']) && $action['file'] != 'unsupported' )
            $offlineSupport = 'yes';
        else
            $offlineSupport = 'no ';

        if( $action['args'] )
            $output = "* ".$action['name'].":value1[,value2...]"; //--- OFF:$offlineSupport  API:$apiSupport \n";
        else
            $output = "* ".$action['name'];//."   --- OFF:$offlineSupport  API:$apiSupport \n";

        $output = str_pad($output, 50);

        $output2 = "| $offlineSupport | $apiSupport |";

        print $output.$output2."\n";

        print str_pad('', 100, '-')."\n";

        //print "\n";
    }

    exit(0);
}

if( isset(PH::$args['listfilters']) )
{
    ksort(RQuery::$defaultFilters['service']);

    print "Listing of supported filters:\n\n";

    foreach(RQuery::$defaultFilters['service'] as $index => &$filter )
    {
        print "* ".$index."\n";
        ksort( $filter['operators'] );

        foreach( $filter['operators'] as $oindex => &$operator)
        {
            //if( $operator['arg'] )
            $output = "    - $oindex";

            print $output."\n";
        }
        print "\n";
    }

    exit(0);
}



if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');



if( ! isset(PH::$args['actions']) )
    display_error_usage_exit('"actions" is missing from arguments');
$doActions = PH::$args['actions'];
if( !is_string($doActions) || strlen($doActions) < 1 )
    display_error_usage_exit('"actions" argument is not a valid string');


if( isset(PH::$args['dryrun'])  )
{
    $dryRun = PH::$args['dryrun'];
    if( $dryRun === 'yes' ) $dryRun = true;
    if( $dryRun !== true || $dryRun !== false )
        display_error_usage_exit('"dryrun" argument has an invalid value');
}

if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}


//
// Rule filter provided in CLI ?
//
if( isset(PH::$args['filter'])  )
{
    $objectsFilter = PH::$args['filter'];
    if( !is_string($objectsFilter) || strlen($objectsFilter) < 1 )
        display_error_usage_exit('"filter" argument is not a valid string');
}



//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, true);
$xmlDoc = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if( $configInput['type'] == 'file' )
{
    if(isset(PH::$args['out']) )
    {
        $configOutput = PH::$args['out'];
        if (!is_string($configOutput) || strlen($configOutput) < 1)
            display_error_usage_exit('"out" argument is not a valid string');
    }
    else
        display_error_usage_exit('"out" is missing from arguments');

    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc = new DOMDocument();
    if( ! $xmlDoc->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{
    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    $xmlDoc = $configInput['connector']->getCandidateConfig();
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
    $pan = new PANConf();
else
    $pan = new PanoramaConf();

print " - Detected platform type is '{$configType}'\n";

if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];
// </editor-fold>



//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $objectsLocation = PH::$args['location'];
    if( !is_string($objectsLocation) || strlen($objectsLocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectsLocation = 'vsys1';
    }
    else
    {
        print " - No 'location' provided so using default ='shared'\n";
        $objectsLocation = 'shared';
    }
}


//
// Extracting actions
//
$explodedActions = explode('/', $doActions);
$doActions = Array();
foreach( $explodedActions as &$exAction )
{
    $newAction = Array();
    $explodedAction = explode(':', $exAction);
    if( count($explodedAction) > 2 )
        display_error_usage_exit('"actions" argument has illegal syntax: '.PH::$args['actions']);
    $newAction['name'] = strtolower($explodedAction[0]);

    if( !isset($supportedActions[$newAction['name']]) )
    {
        display_error_usage_exit('unsupported Action: "'.$newAction['name'].'"');
    }

    if( count($explodedAction) > 1 )
    {
        if( $supportedActions[$newAction['name']]['args'] === false )
            display_error_usage_exit('action "'.$newAction['name'].'" does not accept arguments');
        $newAction['arguments'] = explode(',', $explodedAction[1]);
    }
    else if( $supportedActions[$newAction['name']]['args'] !== false )
        display_error_usage_exit('action "'.$newAction['name'].'" requires arguments');

    $doActions[] = $newAction;
}
//
// ---------


//
// create a RQuery if a filter was provided
//
/**
 * @var RQuery $objectFilterRQuery
 */
$objectFilterRQuery = null;
if( $objectsFilter !== null )
{
    $objectFilterRQuery = new RQuery('service');
    $res = $objectFilterRQuery->parseFromString($objectsFilter, $errorMessage);
    if( $res === false )
    {
        fwrite(STDERR, "\n\n**ERROR** Rule filter parser: " . $errorMessage . "\n\n");
        exit(1);
    }

    print " - Parsing Rule filter and output it after sanitization: ";
    $objectFilterRQuery->display();
    print "\n";
}
// --------------------


//
// load the config
//
$pan->load_from_domxml($xmlDoc);
print "\n*** config loaded ***\n";
// --------------------



//
// Location Filter Processing
//

// <editor-fold desc=" ****  Location Filter Processing  ****" defaultstate="collapsed" >
/**
 * @var RuleStore[] $ruleStoresToProcess
 */
$objectsLocation = explode(',', $objectsLocation);

foreach( $objectsLocation as &$location )
{
    if( strtolower($location) == 'shared' )
        $location = 'shared';
    else if( strtolower($location) == 'any' )
        $location = 'any';
    else if( strtolower($location) == 'all' )
        $location = 'any';
}
$objectsLocation = array_unique($objectsLocation);

$objectsToProcess = Array();

foreach( $objectsLocation as $location )
{
    $locationFound = false;

    if( $configType == 'panos')
    {
        if( $location == 'shared' || $location == 'any'  )
        {
            $objectsToProcess[] = Array('store' => $pan->serviceStore, 'objects' => $pan->serviceStore->all());
            $locationFound = true;
        }
        foreach ($pan->getVirtualSystems() as $sub)
        {
            if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()]) ))
            {
                $objectsToProcess[] = Array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all());
                $locationFound = true;
            }
        }
    }
    else
    {
        if( $location == 'shared' || $location == 'any' )
        {

            $objectsToProcess[] = Array('store' => $pan->serviceStore, 'objects' => $pan->serviceStore->all());
            $locationFound = true;
        }

        foreach( $pan->getDeviceGroups() as $sub )
        {
            if( ($location == 'any' || $location == 'all' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name().'%pre']) )
            {
                $objectsToProcess[] = Array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all() );
                $locationFound = true;
            }
        }
    }

    if( !$locationFound )
    {
        print "ERROR: location '$location' was not found. Here is a list of available ones:\n";
        print " - shared\n";
        if( $configType == 'panos' )
        {
            foreach( $pan->getVirtualSystems() as $sub )
            {
                print " - ".$sub->name()."\n";
            }
        }
        else
        {
            foreach( $pan->getDeviceGroups() as $sub )
            {
                print " - ".$sub->name()."\n";
            }
        }
        print "\n\n";
        exit(1);
    }
}
// </editor-fold>


//
// It's time to process Rules !!!!
//

// <editor-fold desc=" *****  Rule Processing  *****" defaultstate="collapsed" >
foreach( $objectsToProcess as &$objectsRecord )
{
    $ruleStore = $objectsRecord['store'];

    $objects = &$objectsRecord['objects'];

    print "\n* processing store '".$ruleStore->toString()." that holds ".count($objects)." objects\n";


    foreach($objects as $object )
    {
        if( $objectFilterRQuery !== null )
        {
            $queryResult = $objectFilterRQuery->matchSingleObject($object);
            if( !$queryResult )
                continue;
        }

        //mwarning($object->name());

        foreach( $doActions as &$doAction )
        {
            print "\n   - object '" . $object->name() . "' passing through Action='" . $doAction['name'] . "'\n";
            if ($supportedActions[$doAction['name']]['args'] !== false)
            {
                foreach($doAction['arguments'] as $arg)
                {
                    $objectFind = null;


                    if ($configInput['type'] == 'file')
                    {
                        $toEval = $supportedActions[$doAction['name']]['file'];
                        $inputIsAPI = false;
                    } else
                    {
                        $toEval = $supportedActions[$doAction['name']]['api'];
                        $inputIsAPI = true;
                    }

                    if (isset($supportedActions[$doAction['name']]['argObjectFinder']))
                    {
                        $findObjectEval = $supportedActions[$doAction['name']]['argObjectFinder'];
                        $findObjectEval = str_replace('!value!', $arg, $findObjectEval);
                        if (eval($findObjectEval) === false)
                            derr("\neval code was : $findObjectEval\n");
                        if ($objectFind === null)
                            display_error_usage_exit("object named '$arg' not found' with eval code=" . $findObjectEval);
                        $toEval = str_replace('!value!', '$objectFind', $toEval);
                    } else
                        $toEval = str_replace('!value!', $arg, $toEval);

                    if (eval($toEval) === false)
                        derr("\neval code was : $toEval\n");

                    //print $toEval;
                    print "\n";
                }
            } else
            {
                if ($configInput['type'] == 'file')
                    $toEval = $supportedActions[$doAction['name']]['file'];
                else if ($configInput['type'] == 'api')
                    $toEval = $supportedActions[$doAction['name']]['api'];
                else
                    derr('unsupported input type');

                if (eval($toEval) === false)
                    derr("\neval code was : $toEval\n");

            }
        }
    }
}
// </editor-fold>


print "\n **** PROCESSING OF OBJECTS DONE **** \n";

if( isset(PH::$args['stats']) )
{
    $pan->display_statistics();
}


// save our work !!!
if( $configOutput !== null )
{
    $pan->save_to_file($configOutput);
}


print "\n\n*********** END OF SERVICE-EDIT UTILITY **********\n";
print     "**************************************************\n";
print "\n\n";





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


set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." type=panos|panorama in=inputfile.xml out=outputfile.xml location=all|shared|sub ".
        "actions=action1:arg1 ['filter=(from has external) or (to has dmz)']\n";
    print "php ".basename(__FILE__)." listactions   : list supported actions\n";
    print "php ".basename(__FILE__)." listfilters   : list supported filter\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";
    print PH::boldText("\nExamples:\n");
    print " - php ".basename(__FILE__)." type=panorama in=api://192.169.50.10 location=DMZ-Firewall-Group actions=from-add:dmz2,dmz3 'filter=(to has untrust) or (to is.any)'\n";
    print " - php ".basename(__FILE__)." type=panos in=config.xml out=output.xml location=any actions=setSecurityProfile:avProf1\n";

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
$rulesLocation = 'shared';
$rulesFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['type'] = Array('niceName' => 'type', 'shortHelp' => 'specify if config/api is panos or panorama. ie: type=panos  or type=panorama', 'argDesc' => 'panos|panorama');
$supportedArguments['ruletype'] = Array('niceName' => 'ruleType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: ruletype=any  ruletype=security,nat', 'argDesc' => 'all|any|security|nat|decryption');
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['listactions'] = Array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
$supportedArguments['listfilters'] = Array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
$supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters rules based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator value)');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['usedomxml'] = Array('niceName' => 'useDomXML', 'shortHelp' => 'enable alternative XML engine (faster but experimental');


$supportedActions = Array();
// <editor-fold desc="Supported Actions Array" defaultstate="collapsed" >

//                                              //
//                Zone Based Actions            //
//                                              //
$supportedActions['from-add'] = Array(
    'name' => 'from-Add',
    'file' => "\$rule->from->addZone(!value!);",
    'api' => "\$rule->from->API_addZone(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->from->parentCentralStore->find('!value!');"
);
$supportedActions['from-add-force'] = Array(
    'name' => 'from-Add-Force',
    'file' => "\$rule->from->addZone(!value!);",
    'api' => "\$rule->from->API_addZone(!value!);",
    'args' => true,
    'argObjectFinder' => $supportedActions['from-add']['argObjectFinder'].
        "\nif( \$objectFind===null)\n{\$objectFind=\$rule->from->parentCentralStore->findOrCreate('!value!');}\n"
);
$supportedActions['from-remove'] = Array(
    'name' => 'from-Remove',
    'file' => "\$rule->from->removeZone(!value!);",
    'api' => "\$rule->from->API_removeZone(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->from->parentCentralStore->find('!value!');"
);
$supportedActions['from-remove-force-any'] = Array(
    'name' => 'from-Remove-Force-Any',
    'file' => "\$rule->from->removeZone(!value!, true, true);",
    'api' => "\$rule->from->API_removeZone(!value!, true, true);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->from->parentCentralStore->find('!value!');"
);
$supportedActions['to-add'] = Array(
    'name' => 'to-Add',
    'file' => "\$rule->to->addZone(!value!);",
    'api' => "\$rule->to->API_addZone(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->to->parentCentralStore->find('!value!');"
);
$supportedActions['to-add-force'] = Array(
    'name' => 'to-Add-Force',
    'file' => "\$rule->to->addZone(!value!);",
    'api' => "\$rule->to->API_addZone(!value!);",
    'args' => true,
    'argObjectFinder' => $supportedActions['to-add']['argObjectFinder'].
        "\nif( \$objectFind===null)\n{\$objectFind=\$rule->to->parentCentralStore->findOrCreate('!value!');}\n"
);
$supportedActions['to-remove'] = Array(
    'name' => 'to-Remove',
    'file' => "\$rule->to->removeZone(!value!);",
    'api' => "\$rule->to->API_removeZone(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->to->parentCentralStore->find('!value!');"
);
$supportedActions['to-remove-force-any'] = Array(
    'name' => 'to-Remove-Force-Any',
    'file' => "\$rule->to->removeZone(!value!, true, true);",
    'api' => "\$rule->to->API_removeZone(!value!, true, true);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->to->parentCentralStore->find('!value!');"
);
$supportedActions['to-set-any'] = Array(
    'name' => 'to-Set-Any',
    'file' => "\$rule->to->setAny();",
    'api' => "\$rule->to->API_setAny();",
    'args' => false
);
$supportedActions['to-set-any'] = Array(
    'name' => 'to-Set-Any',
    'file' => "\$rule->to->setAny();",
    'api' => "\$rule->to->API_setAny();",
    'args' => false
);


//                                                   //
//                Source/Dest Based Actions          //
//                                                   //
$supportedActions['src-add'] = Array(
    'name' => 'src-Add',
    'file' => "\$rule->source->add(!value!);",
    'api' => "\$rule->source->API_add(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->source->parentCentralStore->find('!value!');"
);
$supportedActions['src-remove'] = Array(
    'name' => 'src-Remove',
    'file' => "\$rule->source->remove(!value!);",
    'api' => "\$rule->source->API_remove(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->source->parentCentralStore->find('!value!');"
);
$supportedActions['src-remove-force-any'] = Array(
    'name' => 'src-Remove-Force-Any',
    'file' => "\$rule->source->remove(!value!, true, true);",
    'api' => "\$rule->source->API_remove(!value!, true, true);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->source->parentCentralStore->find('!value!');"
);
$supportedActions['dst-add'] = Array(
    'name' => 'dst-Add',
    'file' => "\$rule->destination->add(!value!);",
    'api' => "\$rule->destination->API_add(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->destination->parentCentralStore->find('!value!');"
);
$supportedActions['dst-remove'] = Array(
    'name' => 'dst-Remove',
    'file' => "\$rule->destination-remove(!value!);",
    'api' => "\$rule->destination->API_remove(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->destination->parentCentralStore->find('!value!');"
);
$supportedActions['dst-remove-force-any'] = Array(
    'name' => 'dst-Remove-Force-Any',
    'file' => "\$rule->destination-remove(!value!, true, true);",
    'api' => "\$rule->destination->API_remove(!value!, true, true);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->destination->parentCentralStore->find('!value!');"
);
$supportedActions['src-set-any'] = Array(
    'name' => 'src-set-Any',
    'file' => "\$rule->source->setAny();",
    'api' => "\$rule->source->API_setAny();",
    'args' => false
);
$supportedActions['dst-set-any'] = Array(
    'name' => 'dst-set-Any',
    'file' => "\$rule->destination->setAny();",
    'api' => "\$rule->destination->API_setAny();",
    'args' => false
);

//                                                   //
//                Tag property Based Actions       //
//                                                  //
$supportedActions['tag-add'] = Array(
    'name' => 'tag-Add',
    'file' => "\$rule->tags->addTag(!value!);",
    'api' => "\$rule->tags->API_addTag(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->tags->parentCentralStore->find('!value!');"
);
$supportedActions['tag-add-force'] = Array(
    'name' => 'tag-Add-Force',
    'file' => "\$rule->tags->addTag(!value!);",
    'api' => "\$rule->tags->API_addTag(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n
                            if( !\$inputIsAPI )\$objectFind=\$rule->tags->parentCentralStore->findOrCreate('!value!');
                            else {
                               \$objectFind = \$rule->tags->parentCentralStore->find('!value!');
                                if( \$objectFind === null)  \$objectFind = \$rule->tags->parentCentralStore->API_createTag('!value!'); }"
);
$supportedActions['tag-remove'] = Array(
    'name' => 'tag-Remove',
    'file' => "\$rule->tags->removeTag(!value!);",
    'api' => "\$rule->tags->API_removeTag(!value!);",
    'args' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->tags->parentCentralStore->find('!value!');"
);

//                                                   //
//                Services Based Actions       //
//                                                   //
$supportedActions['service-set-appdefault'] = Array(
    'name' => 'service-Set-AppDefault',
    'file' => "\$rule->services->setApplicationDefault();",
    'api' => "\$rule->services->API_setApplicationDefault();",
    'args' => false
);


//                                                   //
//                Log based Actions       //
//                                                   //
$supportedActions['logstart-enable'] = Array(
    'name' => 'logStart-enable',
    'file' => "\$rule->setLogStart(true);",
    'api' => "\$rule->API_setLogStart(true);",
    'args' => false
);
$supportedActions['logstart-disable'] = Array(
    'name' => 'logStart-disable',
    'file' => "\$rule->setLogStart(false);",
    'api' => "\$rule->API_setLogStart(false);",
    'args' => false
);
$supportedActions['logend-enable'] = Array(
    'name' => 'logEnd-enable',
    'file' => "\$rule->setLogEnd(true);",
    'api' => "\$rule->API_setLogEnd(true);",
    'args' => false
);

$supportedActions['logend-disable'] = Array(
    'name' => 'logEnd-disable',
    'file' => "\$rule->setLogEnd(false);",
    'api' => "\$rule->API_setLogEnd(false);",
    'args' => false
);
$supportedActions['logsetting-set'] = Array(
    'name' => 'logSetting-set',
    'file' => "\$rule->setLogSetting('!value!');",
    'api' => "\$rule->API_setLogSetting('!value!');",
    'args' => true
);



//                                                   //
//                Security profile Based Actions       //
//                                                   //
$supportedActions['setsecurityprofile'] = Array(
    'name' => 'setSecurityProfile',
    'file' => "\$rule->setSecurityProfileGroup('!value!');",
    'api' => "\$rule->API_setSecurityProfileGroup('!value!');",
    'args' => true
);


//                                                   //
//                Other property Based Actions       //
//                                                   //
$supportedActions['enable'] = Array(
    'name' => 'enable',
    'file' => "\$rule->setEnabled(true);",
    'api' => "\$rule->API_setEnabled(true);",
    'args' => false
);
$supportedActions['disable'] = Array(
    'name' => 'disable',
    'file' => "\$rule->setEnabled(false);",
    'api' => "\$rule->API_setEnabled(false);",
    'args' => false
);
$supportedActions['delete'] = Array(
    'name' => 'delete',
    'file' => "\$rule->owner->remove(\$rule);",
    'api' => "\$rule->owner->API_remove(\$rule);",
    'args' => false
);
$supportedActions['display'] = Array(
    'name' => 'display',
    'file' => "\$rule->display(7);",
    'api' => "\$rule->display(7);",
    'args' => false
);
$supportedActions['invertpreandpost'] = Array(
    'name' => 'invertPreAndPost',
    'file' => "if( \$rule->owner->isPreRulebase() ) \$rule->owner->moveRuleToPostRulebase(\$rule);
                else if( \$rule->owner->isPostRulebase() ) \$rule->owner->moveRuleToPreRulebase(\$rule);",
    'api' => "if( \$rule->owner->isPreRulebase() ) \$rule->owner->API_moveRuleToPostRulebase(\$rule);
                else if( \$rule->owner->isPostRulebase() ) \$rule->owner->API_moveRuleToPreRulebase(\$rule);",
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

if( isset(PH::$args['usedomxml']) )
{
    PH::enableDomXMLSupport();
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
    ksort(RQuery::$defaultFilters);

    print "Listing of supported filters:\n\n";

    foreach(RQuery::$defaultFilters as $index => &$filter )
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


if( ! isset(PH::$args['type']) )
    display_error_usage_exit('"type" is missing from arguments');
$configType = PH::$args['type'];
if( !is_string($configType) || strlen($configType) < 1 )
    display_error_usage_exit('"type" argument is not a valid string');


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
    $rulesFilter = PH::$args['filter'];
    if( !is_string($rulesFilter) || strlen($rulesFilter) < 1 )
        display_error_usage_exit('"filter" argument is not a valid string');
}


//
// Config is PANOS or Panorama ?
//
$configType = strtolower($configType);
if( $configType != 'panos' && $configType != 'panorama' )
    display_error_usage_exit('"type" has unsupported value: '.$configType);

//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $rulesLocation = PH::$args['location'];
    if( !is_string($rulesLocation) || strlen($rulesLocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print "No 'location' provided so using default ='vsys1'\n";
        $rulesLocation = 'vsys1';
    }
    else
    {
        print "No 'location' provided so using default ='shared'\n";
        $rulesLocation = 'shared';
    }
}

//
// Determine rule types
//
$supportedRuleTypes = Array('all', 'any', 'security', 'nat', 'decryption');
if( !isset(PH::$args['ruletype'])  )
{
    print "No 'ruleType' specified, using 'security' by default\n";
    $ruleTypes = Array('security');
}
else
{
    $ruleTypes = explode(',', PH::$args['ruletype']);
    foreach( $ruleTypes as &$rType)
    {
        $rType = strtolower($rType);
        if( array_search($rType, $supportedRuleTypes) === false )
        {
            display_error_usage_exit("'ruleType' has unsupported value: '".$rType."'. Supported values are: ".PH::list_to_string($supportedRuleTypes));
        }
        if( $rType == 'all' )
            $rType = 'any';
    }

    $ruleTypes = array_unique($ruleTypes);
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
 * @var RQuery $rulesFilterRQuery
 */
$rulesFilterRQuery = null;
if( $rulesFilter !== null )
{
    $rulesFilterRQuery = new RQuery();
    $res = $rulesFilterRQuery->parseFromString($rulesFilter, $errorMessage);
    if( $res === false )
    {
        fwrite(STDERR, "\n\n**ERROR** Rule filter parser: " . $errorMessage . "\n\n");
        exit(1);
    }

    print "Parsing Rule filter and output it after sanitization: ";
    $rulesFilterRQuery->display();
    print "\n";
}
// --------------------


//
// What kind of config input do we have.
//     File or API ?
//
if( $configType == 'panos' )
    $pan = new PANConf();
else
    $pan = new PanoramaConf();
$configInput = PH::processIOMethod($configInput, true);

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

    $pan->load_from_file($configInput['filename']);
}
elseif ( $configInput['type'] == 'api'  )
{
    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    $pan->API_load_from_candidate($configInput['connector']);
}
else
    derr('not supported yet');




//
// Location Filter Processing
//

// <editor-fold desc="Location Filter Processing" defaultstate="collapsed" >
/**
 * @var RuleStore[] $ruleStoresToProcess
 */
$rulesLocation = explode(',', $rulesLocation);

foreach( $rulesLocation as &$location )
{
    if( strtolower($location) == 'shared' )
        $location = 'shared';
    else if( strtolower($location) == 'any' )
        $location = 'any';
    else if( strtolower($location) == 'all' )
        $location = 'any';
}
$rulesLocation = array_unique($rulesLocation);

$rulesToProcess = Array();

foreach( $rulesLocation as $location )
{
    $locationFound = false;

    if( $configType == 'panos')
    {
        foreach ($pan->getVirtualSystems() as $sub)
        {
            if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()]) ))
            {
                if( array_search('any', $ruleTypes) !== false || array_search('security', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->securityRules, 'rules' => $sub->securityRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('nat', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->natRules, 'rules' => $sub->natRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('decryption', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->decryptionRules, 'rules' => $sub->decryptionRules->rules());
                }
                $locationFound = true;
            }
        }
    }
    else
    {
        if( ($location == 'shared' || $location == 'any') && !isset($ruleStoresToProcess['shared%pre'])  )
        {
            if( array_search('any', $ruleTypes) !== false || array_search('security', $ruleTypes) !== false )
            {
                $rulesToProcess[] = Array('store' => $pan->preSecurityRules, 'rules' => $pan->preSecurityRules->rules());
                $rulesToProcess[] = Array('store' => $pan->postSecurityRules, 'rules' => $pan->postSecurityRules->rules());
            }
            if( array_search('any', $ruleTypes) !== false || array_search('nat', $ruleTypes) !== false )
            {
                $rulesToProcess[] = Array('store' => $pan->preNatRules, 'rules' => $pan->preNatRules->rules());
                $rulesToProcess[] = Array('store' => $pan->postNatRules, 'rules' => $pan->postNatRules->rules());
            }
            if( array_search('any', $ruleTypes) !== false || array_search('decryption', $ruleTypes) !== false )
            {
                $rulesToProcess[] = Array('store' => $pan->preDecryptionRules, 'rules' => $pan->preDecryptionRules->rules());
                $rulesToProcess[] = Array('store' => $pan->postDecryptionRules, 'rules' => $pan->postDecryptionRules->rules());
            }
            $locationFound = true;
        }

        foreach( $pan->getDeviceGroups() as $sub )
        {
            if( ($location == 'any' || $location == 'all' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name().'%pre']) )
            {
                if( array_search('any', $ruleTypes) !== false || array_search('security', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->preSecurityRules, 'rules' => $sub->preSecurityRules->rules());
                    $rulesToProcess[] = Array('store' => $sub->postSecurityRules, 'rules' => $sub->postSecurityRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('nat', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->preNatRules, 'rules' => $sub->preNatRules->rules());
                    $rulesToProcess[] = Array('store' => $sub->postNatRules, 'rules' => $sub->postNatRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('decryption', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->preDecryptionRules, 'rules' => $sub->preDecryptionRules->rules());
                    $rulesToProcess[] = Array('store' => $sub->postDecryptionRules, 'rules' => $sub->postDecryptionRules->rules());
                }
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

// <editor-fold desc="Rule Processing" defaultstate="collapsed" >
foreach( $rulesToProcess as &$rulesRecord )
{
    $ruleStore = $rulesRecord['store'];

    $rules = &$rulesRecord['rules'];

    print "\n* processing ruleset '".$ruleStore->toString()." that holds ".count($rules)." rules\n";


    foreach($rules as $rule )
    {
        if( $rulesFilterRQuery !== null )
        {
            $queryResult = $rulesFilterRQuery->matchSingleRule($rule);
            if( !$queryResult )
                continue;
        }

        foreach( $doActions as &$doAction )
        {
            print "   - rule '" . $rule->name() . "' passing through Action='" . $doAction['name'] . "'\n";
            if ($supportedActions[$doAction['name']]['args'] !== false)
            {
                foreach($doAction['arguments'] as $arg)
                {
                    $objectFind = null;


                    if ($configInput['type'] == 'file')
                    {
                        $toEval = $supportedActions[$doAction['name']['file']];
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
                            die("\neval code was : $findObjectEval\n");
                        if ($objectFind === null)
                            display_error_usage_exit("object named '$arg' not found' with eval code=" . $findObjectEval);
                        $toEval = str_replace('!value!', '$objectFind', $toEval);
                    } else
                        $toEval = str_replace('!value!', $arg, $toEval);

                    if (eval($toEval) === false)
                        die("\neval code was : $toEval\n");

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
                    die("\neval code was : $toEval\n");

            }
        }
    }
}
// </editor-fold>


// save our work !!!
if( $configOutput !== null )
{
    $pan->save_to_file($configOutput);
}

print "\n\n";





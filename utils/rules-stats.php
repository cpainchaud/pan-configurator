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
print "************ RULE-STATS UTILITY ****************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR .get_include_path() );
require_once("lib/panconfigurator.php");
require_once("common/actions.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";

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
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');

$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');




PH::processCliArgs();

$nestedQueries = Array();


if( isset(PH::$args['help']) )
{
    $pos = array_search('help', $argv);

    if( $pos === false )
        display_usage_and_exit(false);

    $keys = array_keys($argv);

    if( $pos == end($keys) )
        display_usage_and_exit(false);

    $action = $argv[(array_search($pos, $keys) +1)];

    if( !isset(RuleCallContext::$supportedActions[strtolower($action)]) )
        derr("request help for action '{$action}' but it does not exist");

    $action = & RuleCallContext::$supportedActions[strtolower($action)];

    $args = Array();
    if( isset($action['args']) )
    {
        foreach( $action['args'] as $argName => &$argDetails )
        {
            if( $argDetails['default'] == '*nodefault*' )
                $args[] = "{$argName}";
            else
                $args[] = "[{$argName}]";
        }
    }

    $args = PH::list_to_string($args);
    print "*** help for Action ".PH::boldText($action['name']).":".$args."\n";

    if( isset($action['help']) )
        print $action['help'];

    if( !isset($args) || !isset($action['args']) )
    {
        print "\n\n**No arguments required**";
    }
    else
    {
        print "\nListing arguments:\n\n";
        foreach( $action['args'] as $argName => &$argDetails )
        {
            print "-- ".PH::boldText($argName)." :";
            if( $argDetails['default'] != "*nodefault" )
                print " OPTIONAL";
            print " type={$argDetails['type']}";
            if( isset($argDetails['choices']) )
            {
                print "     choices: ".PH::list_to_string($argDetails['choices']);
            }
            print "\n";
            if( isset($argDetails['help']) )
                print " ".str_replace("\n", "\n ",$argDetails['help']);
            else
                print "  *no help avaiable*";
            print "\n\n";
        }
    }


    print "\n\n";

    exit(0);
}


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


if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');


if( !isset(PH::$args['apitimeout']) )
{
    $apiTimeoutValue = 60;
}
else
    $apiTimeoutValue = PH::$args['apitimeout'];


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

/** @var $inputConnector PanAPIConnector */
$inputConnector = null;

if( $configInput['type'] == 'file' )
{
    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        derr("'loadPanoramaPushedConfig' option cannot used in API/Online mode");
    }
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
    $inputConnector = $configInput['connector'];
    if($debugAPI)
       $inputConnector->setShowApiCalls(true);
    print " - Downloading config from API... ";
    $xmlDoc = $inputConnector->getCandidateConfig($apiTimeoutValue);
    print "OK!\n";
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
{
    $configType = 'panorama';
    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        derr("'loadPanoramaPushedConfig' mode can be used only on Firewalls but Panorama was detected");
    }
}
else
    $configType = 'panos';
unset($xpathResult);

print " - Detected platform type is '{$configType}'\n";

if( $configType == 'panos' )
{
    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        print " - 'loadPanoramaPushedConfig' was requested, downloading it through API...";
        $panoramaDoc = $inputConnector->getPanoramaPushedConfig();

        $xpathResult = DH::findXPath('/panorama/vsys', $panoramaDoc);

        if( $xpathResult === false )
            derr("could not find any VSYS");

        if( $xpathResult->length != 1 )
            derr("found more than 1 <VSYS>");

        $fakePanorama = new PanoramaConf();
        $fakePanorama->_fakeMode = true;
        $inputConnector->refreshSystemInfos();
        $newDGRoot = $xpathResult->item(0);
        $panoramaString = "<config version=\"{$inputConnector->info_PANOS_version}\"><shared></shared><devices><entry name=\"localhost.localdomain\"><device-group>".DH::domlist_to_xml($newDGRoot->childNodes)."</device-group></entry></devices></config>";
        #print $panoramaString;
        $fakePanorama->load_from_xmlstring($panoramaString);

        $pan = new PANConf($fakePanorama);
    }
    else $pan = new PANConf();
}
else
    $pan = new PanoramaConf();

if( $inputConnector !== null )
    $pan->connector = $inputConnector;

// </editor-fold>


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
        print " - No 'location' provided so using default ='vsys1'\n";
        $rulesLocation = 'vsys1';
    }
    else
    {
        print " - No 'location' provided so using default ='shared'\n";
        $rulesLocation = 'shared';
    }
}

//
// Determine rule types
//

$supportedRuleTypes = Array('all', 'any', 'security', 'nat', 'decryption', 'appoverride', 'captiveportal', 'pbf', 'qos', 'dos');
if( !isset(PH::$args['ruletype'])  )
{
    print " - No 'ruleType' specified, using 'security' by default\n";
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
// load the config
//
print " - Loading configuration through PAN-Configurator library... ";
$loadStartMem = memory_get_usage(true);
$loadStartTime = microtime(true);
$pan->load_from_domxml($xmlDoc);
$loadEndTime = microtime(true);
$loadEndMem = memory_get_usage(true);
$loadElapsedTime = number_format( ($loadEndTime - $loadStartTime), 2, '.', '');
$loadUsedMem = convert($loadEndMem - $loadStartMem);
print "OK! ($loadElapsedTime seconds, $loadUsedMem memory)\n";
// --------------------




print "\n";
$pan->display_statistics();
print "\n";
$processedLocations = Array();
foreach( $rulesToProcess as &$record )
{
    if( get_class($record['store']->owner) != 'PanoramaConf' && get_class($record['store']->owner) != 'PANConf' )
    {
        /** @var DeviceGroup|VirtualSystem $sub */
        $sub = $record['store']->owner;
        if( isset($processedLocations[$sub->name()]) )
            continue;
        $processedLocations[$sub->name()] = true;
        $sub->display_statistics();
        echo "\n";
    }
}


print "\n\n************ END OF RULE-STATS UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";





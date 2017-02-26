<?php

echo "\n***********************************************\n";
echo   "*********** ".basename(__FILE__)." UTILITY **********\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");
require_once(dirname(__FILE__).'/common/misc.php');


$doActions = null;
$debugAPI = false;

$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'vsys1|shared|dg1');
$supportedArguments[] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments[] = Array('niceName' => 'Filter', 'shortHelp' => "filters rules based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator value)');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');
$supportedArguments[] = Array('niceName' => 'nlogs', 'shortHelp' => 'nlogs is the amount of logs, increase this value (default=20)');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api://192.168.55.100 location=shared [Actions=display] ['Filter=(subtype eq pppoe)'] ...";

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


if( ! isset(PH::$args['actions']) )
    display_error_usage_exit('"actions" is missing from arguments');
$doActions = PH::$args['actions'];
if( !is_string($doActions) || strlen($doActions) < 1 )
    display_error_usage_exit('"actions" argument is not a valid string');


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
$configInput = PH::processIOMethod(PH::$args['in'], true);
$xmlDoc = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if ( $configInput['type'] == 'api'  )
{
    $apiMode = true;
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


// </editor-fold>




if( !$apiMode )
{
    derr("only API mode is supported");
}

//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $location = PH::$args['location'];
    if( !is_string($location) || strlen($location) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $location = 'vsys1';
    }
    else
    {
        print " - No 'location' provided so using default ='shared'\n";
        $location = 'shared';
    }
}

if( $panc->isPanorama() )
{
    if( $location == 'shared' )
        $childDeviceGroups = $panc->deviceGroups;
    else
        $childDeviceGroups = $findLocation->childDeviceGroups(true);
}


$hours = 1;
date_default_timezone_set("Europe/Berlin");
$time = time() - ($hours * 3600);
$time = date('Y/m/d H:i:s', $time);

if( isset(PH::$args['filter']) )
{
    $query = PH::$args['filter'];
    #print "|".strpos( $query, 'receive_time' )."|\n";
    if( strpos( $query, 'receive_time' ) == false )
    {
        print " - No 'receive_time' provided so using default =(receive_time geq '" . $time . "')\n";
        $query .= 'and ( receive_time geq \'' . $time . '\' )';
    }
}
else
{
    print " - No 'receive_time' provided so using default =(receive_time geq '" . $time . "')\n";
    $query = '( receive_time geq \'' . $time . '\' )';
}

if( isset(PH::$args['nlogs']) )
{
    $nlogs = PH::$args['nlogs'];
    print " - 'nlogs' provided so using nlogs=".$nlogs."\n";
}
else
{
    print " - No 'nlogs' provided so using default = 20\n";
    $nlogs = 20;
}

$con = $panc->connector;





$apiArgs = Array();
$apiArgs['type'] = 'log';
$apiArgs['log-type'] = 'system';
$apiArgs['nlogs'] = $nlogs;
$apiArgs['query'] = $query;

$output = $con->getSystemLog($apiArgs);


if( !empty($output) )
{
    print "\n\n##########################################\n";

    foreach( $output as $log)
    {
        #print_r($log);
        $opaque = Array();
        $opaque2 = Array();

        $subtype = PH::boldText( $log['subtype'] );
        print "time: " . $log['receive_time'] . " - serial: " .  $log['serial'] . " - type: " . $log['type'] . " - subtype: " . $subtype . " - eventid: " .  $log['eventid'] . " - severity: " .  $log['severity']  . "\n";
        #print $log['opaque'] . "\n\n";

        if( $subtype == 'globalprotect' || $subtype == 'general')
        {
            if( strpos( $log['opaque'], '.') <= strpos( $log['opaque'], ':') )
                $opaque = explode( '.', $log['opaque'], 2 );
            else
                $opaque[0] = $log['opaque'];

            if( isset( $opaque[1] ) )
                $opaque2 = explode( ',', $opaque[1] );


            print $opaque[0]."\n";
            if( isset($opaque2[0]) )
                foreach( $opaque2 as $detail)
                    print "  - ".$detail." ";
        }
        else
        {
            print $log['opaque'];
        }
        print "\n\n";

    }


    print "##########################################\n\n\n";
}
else
{
    print "\n\n##########################################\n\n\n";
}








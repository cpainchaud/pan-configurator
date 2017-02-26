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
#$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'vsys1|shared|dg1');
$supportedArguments[] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments[] = Array('niceName' => 'Filter', 'shortHelp' => "filters rules based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator value)');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
$supportedArguments[] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');
#$supportedArguments[] = Array('niceName' => 'nlogs', 'shortHelp' => 'nlogs is the amount of logs, increase this value (default=20)');

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


if( isset(PH::$args['filter']) )
{
    $rulesFilter = PH::$args['filter'];

    $filter_array = Array();
    $filter_array['from'][0] = 'DMZ';
    #$filter_array['from'][1] = 'trust';
    #$filter_array['to'][0] = 'untrust';
}
else
{
    $rulesFilter = null;
    $filter_array = Array();
}

//
// create a RQuery if a filter was provided
//
/**
 * @var RQuery $objectFilterRQuery
 */
$objectFilterRQuery = null;
if( $rulesFilter !== null )
{
    $objectFilterRQuery = new RQuery('rule');
    $res = $objectFilterRQuery->parseFromString($rulesFilter, $errorMessage);
    if( $res === false )
    {
        fwrite(STDERR, "\n\n**ERROR** Rule filter parser: " . $errorMessage . "\n\n");
        exit(1);
    }

    print " - Rule filter after sanitization: ";
    $objectFilterRQuery->display();
    print "\n";
}
// --------------------

$con = $panc->connector;

$apiArgs = Array();
$apiArgs['type'] = 'op';
$apiArgs['cmd'] = '<show><session><meter></meter></session></show>';

$output_session_count = $con->getSession($apiArgs);
#print_r($output_session_count);

//find session count
/*
 <response status="success">
    <result>
        <entry>
            <current>228</current>
            <vsys>1</vsys>
            <maximum>0</maximum>
            <throttled>0</throttled>
        </entry>
    </result>
</response>
 */

//get sessions
$apiArgs = Array();
$apiArgs['type'] = 'op';
$apiArgs['cmd'] = '<show><session><all></all></session></show>';

$output = $con->getSession($apiArgs);

if( !empty($output) )
{
    $session_array = Array();
    foreach( $output as $session )
    {
        if( !empty($filter_array) )
        {
            foreach( $filter_array as $id => $filter )
            {
                foreach( $filter as $content )
                {
                    if( $session[$id] == $content )
                    {
                        if( !isset($session_array[$session['idx']]) )
                            $session_array[$session['idx']] = $session;
                    }
                }
            }
        }
        else
        {
            if( !isset($session_array[$session['idx']]) )
                $session_array[$session['idx']] = $session;
        }
    }
}

ksort( $session_array );
$vsys_count=array();
if( !empty($session_array) )
{
    print "\n\n##########################################\n";

    #print "count: ".count($output)."\n";

    foreach( $session_array as $session)
    {
        $padding = 0;
        $padding = str_pad('', $padding);

        #print_r($session);
        print $padding."*Session ID '{$session['idx']}' -  VSYS  '{$session['vsys-idx']}'\n";
        #print $padding." VSYS  '{$session['vsys-idx']}'\n";
        if( !isset( $vsys_count[$session['vsys-idx']] ) )
            $vsys_count[$session['vsys-idx']] = 1;
        else
            $vsys_count[$session['vsys-idx']]++;

        if( isset($session['security-rule']) )
            print $padding." -Rule named '{$session['security-rule']}'\n";
        else
            print $padding." -Rule named ---------\n";
        print $padding."  From: " .$session['from']."  |  To:  ".$session['to']."\n";
        print $padding."  Source: ".$session['source']."\n";
        print $padding."  Destination: ".$session['dst']."\n";
        print $padding."  Service:  ".$session['dport']."    App:  ".$session['application']."\n";
        #print $padding."  NAT:  ".$session['nat'];
        if( $session['srcnat'] == 'True' )
        {
            print $padding."    srcNAT IP:  ".$session['xsource']."\n";
            print $padding."    sportNAT:  ".$session['xsport']."";
            print $padding."    dportNAT:  ".$session['xdport']."\n";
        }

        if( $session['dstnat'] == 'True' )
        {
            print $padding."    dstNAT IP:  ".$session['xdst']."\n";
            print $padding."    sportNAT:  ".$session['xsport']."";
            print $padding."    dportNAT:  ".$session['xdport']."\n";
        }


        /*
                <application>dns</application>
            <ingress>ethernet1/3.120</ingress>
            <egress>ethernet1/4</egress>
            <vsys-idx>1</vsys-idx>
                <xsource>83.125.63.171</xsource>
                <srcnat>True</srcnat>
                <sport>32855</sport>
                <security-rule>trust.untrust.dns</security-rule>
                <from>guest_wlan</from>
            <proto>17</proto>
                <dst>8.8.8.8</dst>
                <to>untrust</to>
            <state>ACTIVE</state>
                <xdst>8.8.8.8</xdst>
                <nat>True</nat>
            <type>FLOW</type>
            <start-time>Tue Nov 8 14:44:02 2016</start-time>
            <proxy>False</proxy>
            <decrypt-mirror>False</decrypt-mirror>
                <idx>17868</idx>
            <total-byte-count>13508</total-byte-count>
                <dstnat>False</dstnat>
            <vsys>vsys1</vsys>
                <xsport>3042</xsport>
                <xdport>53</xdport>
            <flags>NS</flags>
                <source>192.168.120.254</source>
                <dport>53</dport>
         */

        print "\n\n";
    }

    print "\n filtered session : ".count($session_array)." of ".count($output)."\n";


    print "##########################################\n\n\n";



    if( isset(PH::$args['stats']) )
    {
        print "   Session statistics per VSYS:\n";

        #print_r($vsys_count);
        foreach( $vsys_count as $key => $vsys )
        {
            print "     VSYS '".$key."' : ".$vsys." sessions\n";
        }

        print "\n\n";
    }

}
else
{
    print "\n\n##########################################\n\n\n";
}








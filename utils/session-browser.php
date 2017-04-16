<?php

echo "\n***********************************************\n";
echo   "*********** ".basename(__FILE__)." UTILITY **********\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");
require_once("common/actions.php");

require_once(dirname(__FILE__).'/common/misc.php');

$doActions = null;
$debugAPI = false;

$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'input file ie: in=config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS', 'argDesc' => 'vsys1|shared|dg1');
$supportedArguments[] = Array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
$supportedArguments[] = Array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
$supportedArguments[] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments[] = Array('niceName' => 'Filter', 'shortHelp' => "filters rules based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator value)');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
$supportedArguments[] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');
#$supportedArguments[] = Array('niceName' => 'nlogs', 'shortHelp' => 'nlogs is the amount of logs, increase this value (default=20)');

$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=api://192.168.55.100 location=shared [Actions=display] ['Filter=(subtype eq pppoe)'] ...";


//
// Supported Actions
//
$supportedActions = Array();
// <editor-fold desc="  ****  Supported Actions Array  ****" defaultstate="collapsed" >

$supportedActions['display'] = Array(
    'name' => 'display',
    'GlobalFinishFunction' => function ( SessionCallContext $context )
    {
        $object = $context->object;


        //get sessions
        $apiArgs = Array();
        $apiArgs['type'] = 'op';
        $apiArgs['cmd'] = '<show><session><all></all></session></show>';

        $output = $context->connector->getSession($apiArgs);

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


            foreach( $session_array as $session )
            {
                $padding = 0;
                $padding = str_pad('', $padding);

                #print_r($session);
                print $padding . "*Session ID '{$session['idx']}' -  VSYS  '{$session['vsys-idx']}'\n";
                #print $padding." VSYS  '{$session['vsys-idx']}'\n";
                if( !isset($vsys_count[$session['vsys-idx']]) )
                {
                    $vsys_count[$session['vsys-idx']] = array();
                    $vsys_count[$session['vsys-idx']]['count'] = 1;
                    $vsys_count[$session['vsys-idx']]['name'] = $session['vsys'];
                }

                else
                    $vsys_count[$session['vsys-idx']]['count']++;

                if( isset($session['security-rule']) )
                    print $padding . " -Rule named '{$session['security-rule']}'\n";
                else
                    print $padding . " -Rule named ---------\n";
                print $padding . "  ingress: " . $session['ingress'];
                if( isset($session['egress']) )
                    print "  |  egress:  " . $session['egress'] . "\n";

                print $padding . "  From: " . $session['from'] . "  |  To:  " . $session['to'] . "\n";
                print $padding . "  Source: " . $session['source'] . "\n";
                print $padding . "  Destination: " . $session['dst'] . "\n";
                print $padding . "  Service:  " . $session['dport'] . "    proto: " . $session['proto'] . "    App:  " . $session['application'] . "\n";
                #print $padding."  NAT:  ".$session['nat'];
                if( $session['srcnat'] == 'True' )
                {
                    print $padding . "    srcNAT IP:  " . $session['xsource'] . "\n";
                    print $padding . "    sportNAT:  " . $session['xsport'] . "";
                    print $padding . "    dportNAT:  " . $session['xdport'] . "\n";
                }

                if( $session['dstnat'] == 'True' )
                {
                    print $padding . "    dstNAT IP:  " . $session['xdst'] . "\n";
                    print $padding . "    sportNAT:  " . $session['xsport'] . "";
                    print $padding . "    dportNAT:  " . $session['xdport'] . "\n";
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

            print "\n filtered session : " . count($session_array) . " of " . count($output) . "\n";



            print "##########################################\n\n\n";

        }
        else
        {
            print "\n\n##########################################\n\n\n";
        }


        if( isset(PH::$args['stats']) )
        {
            print "   Session statistics per VSYS:\n";

            #print_r($vsys_count);
            foreach( $vsys_count as $key => $vsys )
            {
                print "     VSYS-IDX '".$key."' (".$vsys['name']."): ".$vsys['count']." sessions\n";
            }

            print "\n\n";
        }

    },
);
// </editor-fold>


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


if( isset(PH::$args['listactions']) )
{
    ksort($supportedActions);

    print "Listing of supported actions:\n\n";

    print str_pad('', 100, '-')."\n";
    print str_pad('Action name', 28, ' ', STR_PAD_BOTH)."|".str_pad("Argument:Type",24, ' ', STR_PAD_BOTH)." |".
        str_pad("Def. Values",12, ' ', STR_PAD_BOTH)."|   Choices\n";
    print str_pad('', 100, '-')."\n";

    foreach($supportedActions as &$action )
    {

        $output = "* ".$action['name'];

        $output = str_pad($output, 28).'|';

        if( isset($action['args']) )
        {
            $first = true;
            $count=1;
            foreach($action['args'] as $argName => &$arg)
            {
                if( !$first )
                    $output .= "\n".str_pad('',28).'|';

                $output .= " ".str_pad("#$count $argName:{$arg['type']}", 24)."| ".str_pad("{$arg['default']}",12)."| ";
                if( isset($arg['choices']) )
                {
                    $output .= PH::list_to_string($arg['choices']);
                }

                $count++;
                $first = false;
            }
        }


        print $output."\n";

        print str_pad('', 100, '=')."\n";

        //print "\n";
    }

    exit(0);
}

if( isset(PH::$args['listfilters']) )
{
    ksort(RQuery::$defaultFilters['session']);

    print "Listing of supported filters:\n\n";

    foreach(RQuery::$defaultFilters['session'] as $index => &$filter )
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
    $sessionFilter = PH::$args['filter'];
    if( !is_string($sessionFilter) || strlen($sessionFilter) < 1 )
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
{
    derr( "Panorama detected - util session-browser.php is working only against a firewall" );
    $configType = 'panorama';
}

else
    $configType = 'panos';
unset($xpathResult);


if( $configType == 'panos' )
    $pan = new PANConf();
else
    $pan = new PanoramaConf();

echo " - Detected platform type is '{$configType}'\n";

if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];


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

if( $pan->isPanorama() )
{
    derr( 'Panorama and sessions? take a firewall please' );

    if( $location == 'shared' )
        $childDeviceGroups = $pan->deviceGroups;
    else
        $childDeviceGroups = $findLocation->childDeviceGroups(true);
}


if( isset(PH::$args['filter']) )
{
    derr( 'argument filter is not supported yet' );
    $sessionFilter = PH::$args['filter'];

    $filter_array = Array();

    //NEED a lot of work
    $filter_array['from'][0] = 'DMZ';
    #$filter_array['from'][1] = 'trust';
    #$filter_array['to'][0] = 'untrust';
}
else
{
    $sessionFilter = null;
    $filter_array = Array();
}





//
// Extracting actions
//
$explodedActions = explode('/', $doActions);
/** @var SessionCallContext[] $doActions */
$doActions = Array();
foreach( $explodedActions as &$exAction )
{
    $explodedAction = explode(':', $exAction);
    if( count($explodedAction) > 2 )
        display_error_usage_exit('"actions" argument has illegal syntax: '.PH::$args['actions']);

    $actionName = strtolower($explodedAction[0]);

    if( !isset($supportedActions[$actionName]) )
    {
        display_error_usage_exit('unsupported Action: "'.$actionName.'"');
    }

    if( count($explodedAction) == 1 )
        $explodedAction[1] = '';


    $context = new SessionCallContext($supportedActions[$actionName], $explodedAction[1]);
    $context->baseObject = $pan;
    if( $configInput['type'] == 'api' )
    {
        $context->isAPI = true;
        $context->connector = $pan->connector;
    }

    $doActions[] = $context;

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
if( $sessionFilter !== null )
{
    $objectFilterRQuery = new RQuery('session');
    $res = $objectFilterRQuery->parseFromString($sessionFilter, $errorMessage);
    if( $res === false )
    {
        fwrite(STDERR, "\n\n**ERROR** Session filter parser: " . $errorMessage . "\n\n");
        exit(1);
    }

    print " - Session filter after sanitization: ";
    $objectFilterRQuery->display();
    print "\n";
}
// --------------------

#$con = $pan->connector;

$first  = true;
foreach( $doActions as $doAction )
{
    if( $doAction->hasGlobalFinishAction() )
    {
        $first = false;
        $doAction->executeGlobalFinishAction();
    }
}



print "\n\n\n************ END OF SESSION-BROWSER UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";



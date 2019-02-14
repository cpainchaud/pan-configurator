<?php
/**
 * Created by PhpStorm.
 * User: swaschkut
 * Date: 4/19/16
 * Time: 9:12 AM
 */


print "\n***********************************************\n";
print "************ APP-ID ENABLE UTILITY ****************\n\n";


require_once("lib/panconfigurator.php");



function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
        "custom_url_category=test\n";
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


function disable_appid( $actions, $xmlDoc1, $configInput, $Connector)
{
    $tmp_application_status = DH::findXPath( '/config/shared/application-status/entry', $xmlDoc1 );

    if(  $tmp_application_status->length == 0  )
    {
        //THIS is a NON available XPATH | TODO: swaschkut 20190115 validate it!!!
        $tmp_application_status = DH::findXPath( '/config/devices/entry/vsys/entry/application-status/entry', $xmlDoc1 );
        if(  $tmp_application_status->length == 0  )
            print PH::boldText( "\nNO disabled APP-IDs available\n" );
    }


    foreach( $tmp_application_status as $app_status )
    {
        print "----------------\n";
        print "name: ".DH::findAttribute( 'name', $app_status)."\n";


        if( $actions == 'display' )
            print " - status: ".DH::findAttribute( 'status', $app_status);
        elseif( $actions == 'enable' )
        {
            $apiArgs = Array();
            $apiArgs['type'] = 'op';
            $apiArgs['cmd'] = '<request><set-application-status-recursive><application>'.DH::findAttribute( 'name', $app_status).'</application><status>enabled</status></set-application-status-recursive></request>';

            if( $configInput['type'] == 'api' )
            {
                $response = $Connector->sendRequest($apiArgs);
                print " - status: enable";
            }
            else
                derr( "this script is working only in API mode\n" );
        }

        print "\n";
    }
}

print "\n";

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = false;
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['cycleconnectedfirewalls'] = Array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides' );
$supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each disabled app-id. ie: actions=display / actions=enable', 'argDesc' => 'action:arg1[,arg2]' );


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


if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if(isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if (!is_string($configOutput) || strlen($configOutput) < 1)
        display_error_usage_exit('"out" argument is not a valid string');
}

if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

if( isset(PH::$args['cycleconnectedfirewalls'])  )
    $cycleConnectedFirewalls = true;
else
    $cycleConnectedFirewalls = false;

if( ! isset(PH::$args['actions']) || strtolower( PH::$args['actions'] ) == 'display')
    $actions = 'display';
elseif( strtolower( PH::$args['actions'] ) == 'enable' )
    $actions = 'enable';

################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, true);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( ! $xmlDoc1->load($configInput['filename']) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{

    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    print " - Downloading config from API... ";

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        print " - 'loadPanoramaPushedConfig' was requested, downloading it through API...";
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    $hostname = $configInput['connector']->info_hostname;

    /** @var PanAPIConnector $inputConnector */
    $inputConnector = $configInput['connector'];

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );

    print "OK!\n";

}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult1 = DH::findXPath('/config/devices/entry/vsys', $xmlDoc1);
if( $xpathResult1 === FALSE )
    derr('XPath error happened');
if( $xpathResult1->length <1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length <1 )
        $configType = 'panorama';
    else
        $configType = 'pushed_panorama';
}
else
    $configType = 'panos';
unset($xpathResult1);

print " - Detected platform type is '{$configType}'\n";

############## actual not used

if( $configType == 'panos' )
    $pan = new PANConf();
elseif( $configType == 'panorama' )
    $pan = new PanoramaConf();



if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];






// </editor-fold>

################


//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $objectslocation = PH::$args['location'];
    if( !is_string($objectslocation) || strlen($objectslocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'panorama' )
    {
        print " - No 'location' provided so using default ='shared'\n";
        $objectslocation = 'shared';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
}



##########################################
##########################################

if($cycleConnectedFirewalls && $configType == 'panorama')
{
    $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();

    $countFW = 0;
    foreach( $firewallSerials as $fw )
    {
        $countFW++;
        print " ** Handling FW #{$countFW}/".count($firewallSerials)." : serial/{$fw['serial']}   hostname/{$fw['hostname']} **\n";
        $tmpConnector = $inputConnector->cloneForPanoramaManagedDevice($fw['serial']);

        if($debugAPI)
            $tmpConnector->setShowApiCalls(true);
        $xmlDoc1 = $tmpConnector->getCandidateConfig();

##############
        disable_appid( $actions, $xmlDoc1, $configInput, $tmpConnector );
    }
}
else
{
    $pan->load_from_domxml($xmlDoc1);
##############
    disable_appid( $actions, $xmlDoc1, $configInput, $pan->connector );
}







##############################################

print "\n\n\n";

// save our work !!!
if( $configOutput !== null )
{
    if( $configOutput != '/dev/null' )
    {
        $pan->save_to_file($configOutput);
    }
}



print "\n\n************ END OF APP-ID ENABLE UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";

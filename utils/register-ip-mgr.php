<?php

echo "\n***********************************************\n";
echo   "*********** ".basename(__FILE__)." UTILITY **************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");
require_once(dirname(__FILE__).'/common/misc.php');

$debugAPI = false;

$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'Action', 'shortHelp' => 'type of action you want to perform against API', 'argDesc' => 'display');
$supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'the target PANOS device ie: in=api://1.2.3.4', 'argDesc' => 'api://[hostname or IP]');
$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'defines the VSYS target of the UserID request', 'argDesc' => 'vsys1[,vsys2,...]');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');


$supportedArguments[] = Array('niceName' => 'records', 'shortHelp' => 'list of userid records to register/unregister in API', 'argDesc' => '10.0.0.1,domain\user2/10.2.3.4,domain\user3');
$supportedArguments[] = Array('niceName' => 'recordFile', 'shortHelp' => 'use a text file rather than CLI to input UserID records', 'argDesc' => 'users.txt');


$usageMsg = PH::boldText('USAGE EXAMPLES: ')."\n - php ".basename(__FILE__)." in=api://1.2.3.4 action=register location=vsys1 records=10.0.0.1,domain\\user2/10.2.3.4,domain\\user3"
    ."\n - php ".basename(__FILE__)." in=api://1.2.3.4 action=register location=vsys1 recordFile=users.txt";

prepareSupportedArgumentsArray($supportedArguments);

PH::processCliArgs();

// check that only supported arguments were provided
foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
        display_error_usage_exit("unsupported argument provided: '$index'");
}

if( isset(PH::$args['help']) )
    display_usage_and_exit();


if( !isset(PH::$args['in']) )
    display_error_usage_exit(' "in=" argument is missing');


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



/** @var PanAPIConnector $connector */
$connector = null;

if( $configInput['type'] == 'file' )
{
    derr("Only API method is supported for input, please fix your 'in' argument");

}
elseif ( $configInput['type'] == 'api'  )
{
    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    print " - Downloading config from API... ";
    $xmlDoc = $configInput['connector']->getCandidateConfig();
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
    $pan = new PANConf();
else
    $pan = new PanoramaConf();

print " - Detected platform type is '{$configType}'\n";

if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];
    $connector = $pan->connector;
// </editor-fold>

// </editor-fold>

echo " - Connected to API at {$connector->apihost} / {$connector->info_hostname}\n";
echo " - PANOS version: {$connector->info_PANOS_version}\n";
echo " - PANOS model: {$connector->info_model}\n";
echo "\n";



if( !isset(PH::$args['action']) )
    display_error_usage_exit("no 'action' was defined");

$location = 'vsys1';
if( !isset(PH::$args['location']) )
    echo " - no 'location' was provided, using default VSYS1\n";
else
{
    $location = PH::$args['location'];
    echo " - location '{$location}' was provided\n";
}



$action = strtolower(PH::$args['action']);

if( $action == 'display' )
{
    echo " - action is '$action'\n";
    print "\n\n\n";


    $pan->load_from_domxml($xmlDoc);
    foreach( $pan->getVirtualSystems() as $sub )
    {
        echo "\n - ".$sub->name()."\n";

        print "     - IPs: \n";
        $register_ip_array = $connector->register_getIp( $sub->name() );
        foreach ( $register_ip_array  as $ip => $reg )
        {
            $first_value = reset($reg); // First Element's Value
            $first_key = key($reg); // First Element's Key

            print "          ".$ip." - ".$first_key."\n";
        }


        $vsys = $pan->findVirtualSystem( $sub->name() );
        $address_groups = $vsys->addressStore->addressGroups();
        print "     - DAGs: \n";
        foreach( $address_groups as $addressGroup)
        {
            if( $addressGroup->isDynamic() )
            {
                $tags = $addressGroup->tags->tags();

                print "          ".$addressGroup->name()." filter: ".$addressGroup->filter."\n";

            }
        }

        $dynamicAddressGroup_array = $connector->dynamicAddressGroup_get( $sub->name() );
        print "REGISTERED-IP:\n";
        print_r( $register_ip_array );
        print "DAG with registered-ip:\n";
        print_r( $dynamicAddressGroup_array );

    }
}
else
    derr("action '{$action}' is not supported");





echo "\n\n***********************************************\n";
echo "************* END OF SCRIPT ".basename(__FILE__)." ************\n";
echo "***********************************************\n\n";


<?php

echo "\n***********************************************\n";
echo   "*********** ".basename(__FILE__)." UTILITY **************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");
require_once(dirname(__FILE__).'/common/misc.php');

$debugAPI = false;

$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'Actions', 'shortHelp' => 'type of action you want to perform against API', 'argDesc' => 'display');
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



if( !isset(PH::$args['actions']) )
    display_error_usage_exit("no 'action' was defined");

$location = 'vsys1';
if( !isset(PH::$args['location']) )
    echo " - no 'location' was provided, using default VSYS1\n";
else
{
    $location = PH::$args['location'];
    echo " - location '{$location}' was provided\n";
}



$action = strtolower(PH::$args['actions']);

if( $action == 'display' || $action == 'unregister-unused')
{
    echo " - action is '$action'\n";
    print "\n\n\n";

    $unregister_array = array();

    $pan->load_from_domxml($xmlDoc);
    $virtualsystems = $pan->getVirtualSystems();
    foreach( $virtualsystems as $sub )
    {
        $unregister_array[$sub->name()] = array();

        print "\n\n##################################\n";
        echo PH::boldText( " - ".$sub->name()."\n" );

        $register_ip_array = $connector->register_getIp( $sub->name() );
        print "     - registered-ips: [".count($register_ip_array)."]\n";

        foreach ( $register_ip_array  as $ip => $reg )
        {
            $first_value = reset($reg); // First Element's Value
            $first_key = key($reg); // First Element's Key

            print "          ".$ip." - ".$first_key."\n";
        }


        $vsys = $pan->findVirtualSystem( $sub->name() );
        $address_groups = $vsys->addressStore->addressGroups();

        $shared_address_groups = $pan->addressStore->addressGroups();

        $address_groups = array_merge( $shared_address_groups, $address_groups );
        print "     - DAGs: \n";
        /*
        foreach( $shared_address_groups as $addressGroup)
        {
            if( $addressGroup->isDynamic() )
            {
                print "          ".$addressGroup->name()." filter: ".$addressGroup->filter."\n";
            }
        }
        */
        $dynamicAddressGroup_array = array();
        foreach( $address_groups as $addressGroup)
        {
            if( $addressGroup->isDynamic() )
            {
                $tags = $addressGroup->tags->tags();

                print "          ".$addressGroup->name()." filter: ".$addressGroup->filter."\n";

                $dynamicAddressGroup_array = $connector->dynamicAddressGroup_get( $sub->name() );
                if( isset( $dynamicAddressGroup_array[$addressGroup->name()] ) )
                    foreach( $dynamicAddressGroup_array[$addressGroup->name()] as $key => $members )
                    {
                        if( $key != 'name' )
                        {
                            print "           - ".$key."\n";
                        }

                    }

            }
        }


        print "\n\n----------------------------------\n";
        print "VALIDATION:\n\n";

        if( empty( $register_ip_array ) )
        {
            #print "nothing registered\n";
        }
        else
        {
            #print "which registered-ip can be deleted because:\n";
            #print "  - no DAG for tag is available\n";
            #print "  - DAG is not used, so no registered-ip for DAG\n";


            foreach ( $register_ip_array  as $ip => $reg )
            {
                $first_value = reset($reg); // First Element's Value
                $first_key = key($reg); // First Element's Key

                foreach( $dynamicAddressGroup_array as $key => $group )
                {
                    #print "KEY: ".$key."\n";
                    #print_r( $group );
                    if( !isset( $group[$ip] )  )
                    {
                        $unregister_array[$sub->name()][$ip] = $reg;
                        #print "unregister: ".$ip."\n";
                    }
                    else
                    {
                        #print "unset: ".$ip."\n";
                        unset( $unregister_array[$sub->name()][$ip] );
                        break;
                    }
                }
            }
        }


        print "possible IPs for UNREGISTER:\n";
        #print_r( $unregister_array );
        foreach( $unregister_array[$sub->name()] as $unregister_ip => $tags )
        {
            print " - ".$unregister_ip."\n";
        }

        print "DAGs can be deleted (because they are not used in Ruleset):\n";
        foreach( $dynamicAddressGroup_array as $key => $group )
        {
            if( count( $group ) <= 1 )
                print " - ".$key . "\n";
        }
    }
}
elseif( $action == 'fakeregister' )
{
    $numberOfIPs = 499;
    $tag = 'fake';
    $startingIP = ip2long('10.0.0.0');

    $records = Array();


    echo "  - Generating {$numberOfIPs} fake records starting at IP ".long2ip($startingIP)."... ";
    for($i=1; $i<= $numberOfIPs; $i++)
    {
        $records[long2ip($startingIP+$i)] = array( $tag );
    }
    echo "OK!\n";


    echo " - now sending records to API ... ";
    $connector->register_sendUpdate( $records, null, 'vsys1' );
    echo "OK!\n";

}
else
    derr("action '{$action}' is not supported");


if(  $action == 'unregister-unused')
{
    foreach( $virtualsystems as $sub )
    {
        echo " - now sending records to API ... ";
        $connector->register_sendUpdate(null, $unregister_array[$sub->name()], $sub->name());
        echo "OK!\n";
    }
}






echo "\n\n***********************************************\n";
echo "************* END OF SCRIPT ".basename(__FILE__)." ************\n";
echo "***********************************************\n\n";


<?php
/**
 * Created by PhpStorm.
 * User: swaschkut
 * Date: 4/19/16
 * Time: 9:12 AM
 */


print "\n***********************************************\n";
print "************ COMMIT-CONFIG UTILITY ****************\n\n";


require_once("lib/panconfigurator.php");



function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml location=vsys1 ".
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";
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
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['template'] = Array('niceName' => 'template', 'shortHelp' => 'Panorama template');
$supportedArguments['loadpanoramapushedconfig'] = Array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules' );
$supportedArguments['folder'] = Array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


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

if( isset(PH::$args['folder'])  )
{
    $offline_folder = PH::$args['folder'];
}

if( isset(PH::$args['template'])  )
{
    $template = PH::$args['template'];
}

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
    if( ! $xmlDoc1->load($configInput['filename'], XML_PARSE_BIG_LINES) )
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

$pan->load_from_domxml($xmlDoc1);

if( $configType == 'panorama' )
{
    if( ! isset(PH::$args['template']) )
    {
        derr( '"template" is missing from arguments' );
    }
}

##############

if( $configType == 'panos' )
{
    $allsub = $pan->virtualSystems;
}
elseif( $configType == 'panorama' )
{
    $template = $pan->findTemplate( $template );
    $allsub = $template->deviceConfiguration->virtualSystems;
}


/*

<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
         <interface>
         </interface>
         <virtual-wire>
          <entry name="qa-vwire">
            <interface1>ethernet1/3</interface1>
            <interface2>ethernet1/4</interface2>
            <tag-allowed>0-4094</tag-allowed>
            <multicast-firewalling>
              <enable>yes</enable>
            </multicast-firewalling>
            <link-state-pass-through>
              <enable>yes</enable>
            </link-state-pass-through>
          </entry>
          <entry name="prod-vwire">
            <interface1>ethernet1/1</interface1>
            <interface2>ethernet1/2</interface2>
            <tag-allowed>0-4094</tag-allowed>
            <multicast-firewalling>
              <enable>yes</enable>
            </multicast-firewalling>
            <link-state-pass-through>
              <enable>yes</enable>
            </link-state-pass-through>
          </entry>
        </virtual-wire>
 */

print "\n\nvwire: \n\n";

$virtualWires = $pan->network->virtualWireStore->virtualWires();

foreach( $virtualWires as $virtualWire)
{
    print $virtualWire->name()." - ";

    print $virtualWire->attachedInterface1." - ";
    print $virtualWire->attachedInterface2."\n";

}


$interface_wo_vsys = array();

foreach( $allsub as $virtualSystem )
{
    print "\n\nVSYS name: ".$virtualSystem->name()."\n";

    foreach( $virtualSystem->importedInterfaces as $interfacecontainer )
    {
        if (is_a($interfacecontainer, 'NetworkPropertiesContainer'))
        {
            foreach( $interfacecontainer->getAllInterfaces() as $interface )
            {
                $tmp_vsys = $interfacecontainer->findVsysInterfaceOwner( $interface->name() );
                if( $tmp_vsys  != null )
                {
                    if( $tmp_vsys->name() == $virtualSystem->name() )
                    {
                        print "\n  - ".$interface->type . " - ";
                        if( $interface->type == "layer3" )
                        {
                            if( $interface->isSubInterface() )
                                print "subinterface - ";
                            else
                                print "count subinterface: " . $interface->countSubInterfaces() . " - ";
                        }
                        elseif( $interface->type == "aggregate-group" )
                        {
                            #$interface->
                        }

                        print $interface->name() . ", ip-addresse(s): ";
                        if( $interface->type == "layer3" )
                        {
                            foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                                print $ip_address . ",";
                        }
                        elseif( $interface->type == "tunnel"  )
                        {
                            foreach( $interface->getIPv4Addresses() as $ip_address )
                                print $ip_address . ",";
                        }
                    }
                }
                else
                    $interface_wo_vsys[ $interface->name() ] = $interface;
            }
        }
    }
}


print "\n\nall interfaces NOT attached to an vsys:\n";
foreach( $interface_wo_vsys as $interface )
{
    print "\n  - ".$interface->type . " - ";
    if( $interface->type == "layer3" )
    {
        if( $interface->isSubInterface() )
            print "subinterface - ";
        else
            print "count subinterface: " . $interface->countSubInterfaces() . " - ";
    }
    elseif( $interface->type == "aggregate-group" )
    {
        #$interface->
    }

    print $interface->name() . ", ip-address(es): ";
    if( $interface->type == "layer3" )
    {
        foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
            print $ip_address . ",";
    }
    elseif( $interface->type == "tunnel"  )
    {
        foreach( $interface->getIPv4Addresses() as $ip_address )
            print $ip_address . ",";
    }

    #print "\n";
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



print "\n\n************ END OF COMMIT-CONFIG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";

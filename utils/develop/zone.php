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
        $objectslocation = 'vsys1';
    }
    elseif( $configType == 'pushed_panorama' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectslocation = 'vsys1';
    }
}



##########################################
##########################################
$zone_array = array();


$pan->load_from_domxml($xmlDoc1);

if( $configType == 'panorama' )
{
    if( ! isset(PH::$args['template']) )
        derr( '"template" is missing from arguments' );
}
else
    $template = "all";


if( ($template == 'all' || $template == "any") &&  $configType == 'panorama' )
        $template_array = $pan->templates;
else
    $template_array = explode( ",", $template);



foreach( $template_array as $template)
{
    if( $objectslocation == "all" || $objectslocation == "any" || is_object( $objectslocation))
    {
        if( $configType == 'panos' )
            $tmp_location_array = $pan->virtualSystems;
        elseif( $configType == 'panorama' )
        {
            if( !is_object( $template) )
                $template = $pan->findTemplate( $template );

            $tmp_location_array = $template->deviceConfiguration->virtualSystems;
        }
    }
    else
        $tmp_location_array = explode( ",", $objectslocation);


##############
//print "\n#######################################################################################################################\n";
    //DISPLAY
    print "\n\n----------------------\n";
    if( is_object( $template) )
        print "TEMPLATE: ". PH::boldText( $template->name() )."\n";

    foreach( $tmp_location_array as $objectslocation )
    {
        if( is_object( $objectslocation) )
            $sub = $objectslocation;
        else
        {
            if( $configType == 'panos' )
                $sub = $pan->findVirtualSystem($objectslocation);
            elseif( $configType == 'panorama' )
            {
                if( !is_object( $template) )
                    $template = $pan->findTemplate( $template );

                $sub = $template->deviceConfiguration->findVirtualSystem($objectslocation);
            }
        }

        if( $sub != null )
        {
            #print "\n\n----------------------\n";
            print "VSYS: ".PH::boldText( $sub->name() )."\n";



            print "  ZONES: \n";
            foreach( $sub->zoneStore->getAll() as $zone )
            {
                print "   - ".PH::boldText( $zone->name() ) . "   ( type: ".$zone->_type." )";

                if( $configType == 'panorama' )
                {
                    $zone_array[$zone->name()][$template->name()]['vsys'] = $sub->name();

                    //Todo: extend pan-c with template-stack and check templatestack membership and also other template members
                    #$zone_array[$zone->name()][$template->name()]['parent'] = $template->
                }
                else
                    $zone_array[$zone->name()] = $sub->name();




                //DISPLAY interfaces attached to zones
                $interfaces = $zone->attachedInterfaces;
                foreach( $interfaces->getAll() as $interface )
                {
                    print "\n    - ".$interface->type . " - ";
                    print $interface->name();
                    /*if( $interface->type == "layer3" )
                    {
                        if( count( $interface->getLayer3IPv4Addresses() ) > 0 )
                            print ", ip-addresse(s): ";
                        foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                            print $ip_address.",";
                    }*/
                    if( $interface->type == "layer3" )
                    {
                        print ", ip-addresse(s): ";
                        foreach( $interface->getLayer3IPv4Addresses() as $ip_address )
                            print $ip_address . ",";
                    }
                    elseif( $interface->type == "tunnel" || $interface->type == "loopback" || $interface->type == "vlan"  )
                    {
                        print ", ip-addresse(s): ";
                        foreach( $interface->getIPv4Addresses() as $ip_address )
                        {
                            if( strpos( $ip_address, "." ) !== false )
                                print $ip_address . ",";
                            else
                            {
                                $object = $sub->addressStore->find( $ip_address );
                                print $ip_address." ({$object->value()}) ,";
                            }
                        }
                    }
                    elseif( $interface->type == "auto-key" )
                    {
                        print " - IPsec config";
                        print " - IKE gateway: " . $interface->gateway;
                        print " - interface: " . $interface->interface;
                    }

                }


                print "\n\n";
            }
        }
    }
}


//print "\n#######################################################################################################################\n";
print "\n\n\n";
#print_r( $zone_array );

if( $configType == 'panorama' )
{
    foreach( $zone_array as $zone_name => $zone )
    {
        if( count( $zone ) > 1 )
        {
            print "\n\nZone: ".PH::boldText( $zone_name )."\n";
            foreach( $zone as $template_name => $vsys )
            {
                print "   Template: ".$template_name;

                if( isset($vsys['vsys']) )
                    print " - vsys: ".$vsys['vsys'];

                if( isset($vsys['parent']) )
                    print " - parent template: ".$vsys['parent'];
                print "\n";
            }
        }
    }
}

//print "\n#######################################################################################################################\n";


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

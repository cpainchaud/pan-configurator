<?php
/**
 * Created by PhpStorm.
 * User: swaschkut
 * Date: 4/19/16
 * Time: 9:12 AM
 */


print "\n***********************************************\n";
print "************ DOWNLOAD predefined.xml UTILITY ****************\n\n";


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
$inputConnector = null;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['location'] = Array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');



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



if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

if( isset(PH::$args['folder'])  )
{
    $offline_folder = PH::$args['folder'];
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
    #derr( "offline file not supported\n" );
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

$request = 'type=config&action=get&xpath=%2Fconfig%2Fpredefined';

try
{
    $candidateDoc = $configInput['connector']->sendSimpleRequest($request);
}
catch(Exception $e)
{
    PH::disableExceptionSupport();
    print " ***** an error occured : ".$e->getMessage()."\n\n";
}


//make XMLroot for <predefined>
$predefinedRoot = DH::findFirstElement('response', $candidateDoc);
if( $predefinedRoot === FALSE )
    derr("<response> was not found", $candidateDoc);

$predefinedRoot = DH::findFirstElement('result', $predefinedRoot);
if( $predefinedRoot === FALSE )
    derr("<result> was not found", $predefinedRoot);

$predefinedRoot = DH::findFirstElement('predefined', $predefinedRoot);
if( $predefinedRoot === FALSE )
    derr("<predefined> was not found", $predefinedRoot);


$xmlDoc = new DomDocument;
$xmlDoc->appendChild($xmlDoc->importNode($predefinedRoot, true));



################################################################################################


$cursor = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);


$exernal_version = $cursor->nodeValue;
$panc_version = $pan->appStore->predefinedStore_appid_version;


$external_appid = explode( "-", $exernal_version );
$pan_c_appid = explode( "-", $panc_version );




if( intval( $pan_c_appid[0] ) >  intval( $external_appid[0] ) )
{
    print "\n\n - pan-configurator has already a newer APP-id version '".$panc_version."' installed. Device App-ID version: ".$exernal_version."\n";
}
elseif( intval( $pan_c_appid[0] ) ==  intval( $external_appid[0] ) )
{
    print "\n\n - same app-id version '".$panc_version."' available => do nothing\n";
}
else
{
    print "\n\n - pan-c has an old app-id version '".$panc_version."' available. Device App-ID version: ".$exernal_version."\n";

    $predefined_path = '/../lib/object-classes/predefined.xml';

    print "\n\n *** predefined.xml is saved to '".__DIR__ . $predefined_path."''\n\n";
    file_put_contents ( __DIR__ . $predefined_path , $xmlDoc->saveXML());
}








print "\n\n************ END OF DOWNLOAD predefined.xml UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";


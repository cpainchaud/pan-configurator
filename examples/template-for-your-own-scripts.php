<?php

print "\n*********** START OF SCRIPT ".basename(__FILE__)." ************\n\n";

// load PAN-Configurator library
require_once("lib/panconfigurator.php");

PH::processCliArgs();

if( !isset(PH::$args['location']) )
    derr("missing 'location' argument, please specify a vsys or device-group name");

if( !isset(PH::$args['in']) )
    derr("missing 'in' argument");
if( !is_string(PH::$args['in']) || strlen(PH::$args['in']) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if( isset(PH::$args['debugapi'])  )
    $debugAPI = true;
else
    $debugAPI = false;

$configInput = PH::processIOMethod(PH::$args['in'], true);
if( $configInput['status'] == 'fail' )
    derr($configInput['msg']);


if( $configInput['type'] == 'file' )
{
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

/*********************************
 * *
 * *  START WRITING YOUR CODE HERE
 * *
 * * List of available variables:
 * * $pan : PANConf or PanoramaConf object
 * * $sub : DeviceGroup or VirtualSystem found after looking from cli 'location' argument
 * * PH::$args : array with all CLI arguments processed by PAN-Configurator
 * *
 */



print "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";


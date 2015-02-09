<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/


set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." type=panos|panorama in=inputfile.xml out=outputfile.xml location=all|shared|sub ".
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']\n";
    print "php ".basename(__FILE__)." listactions   : list supported actions\n";
    print "php ".basename(__FILE__)." listfilters   : list supported filter\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";
    print PH::boldText("\nExamples:\n");
    print " - php ".basename(__FILE__)." type=panorama in=api://192.169.50.10 location=DMZ-Firewall-Group actions=displayReferences 'filter=(name eq Mail-Host1)'\n";
    print " - php ".basename(__FILE__)." type=panos in=config.xml out=output.xml location=any actions=delete\n";

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

$configInput = null;
$configOutput = null;
$errorMessage = '';
$debugAPI = false;
$loadConfigAfterUpload = false;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['loadafterupload'] = Array('niceName' => 'loadAfterUpload', 'shortHelp' => 'load configuration after upload happened');
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

if( ! isset(PH::$args['out']) )
    display_error_usage_exit('"out" is missing from arguments');
$configOutput = PH::$args['out'];
if( !is_string($configOutput) || strlen($configOutput) < 1 )
    display_error_usage_exit('"out" argument is not a valid string');


if( isset(PH::$args['loadafterupload']) )
{
    $loadConfigAfterUpload = true;
}




if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}



$doc = new DOMDocument();

print "Opening/downloading original configuration...";

//
// What kind of config input do we have.
//     File or API ?
//
$configInput = PH::processIOMethod($configInput, true);

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

if( $configInput['type'] == 'file' )
{
    $doc->Load($configInput['filename']);
}
elseif ( $configInput['type'] == 'api'  )
{
    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);
    $configInput['connector']->getCandidateConfig();
}
else
    derr('not supported yet');


print " OK!!\n\n";


print "Now saving/uploading that configuration to ";


//
// What kind of config input do we have.
//     File or API ?
//
$configOutput = PH::processIOMethod($configOutput, false);

if( $configOutput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configOutput['msg'] . "\n\n");exit(1);
}

if( $configOutput['type'] == 'file' )
{
    print "{$configOutput['filename']} ... ";
    $doc->save($configOutput['filename']);
}
elseif ( $configOutput['type'] == 'api'  )
{
    if($debugAPI)
        $configOutput['connector']->setShowApiCalls(true);

    if( $configOutput['filename'] !== null )
        $saveName = $configOutput['filename'];
    else
        $saveName = 'stage0.xml';

    print "{$configOutput['connector']->apihost}/$saveName ... ";

    $configOutput['connector']->uploadConfiguration(DH::firstChildElement($doc), $saveName, false);
}
else
    derr('not supported yet');

print "OK!\n";


if( $loadConfigAfterUpload )
{
    print "Loading config in the firewall (will display warnings if any....\n";
    $xmlResponse = $configOutput['connector']->sendCmdRequest('<load><config><from>' . $saveName . '</from></config></load>');

    $xmlResponse = DH::firstChildElement($xmlResponse);

    if( $xmlResponse === false )
        derr('unexpected error !');

    $msgElement = DH::findFirstElement('msg', $xmlResponse);

    if( $msgElement !== false )
    {
        foreach($msgElement->childNodes as $msg )
        {
            if( $msg->nodeType != 1)
                continue;

            print " - ".$msg->nodeValue."\n";
        }
    }
}


print "********************* DONE *********************";
print "\n\n";





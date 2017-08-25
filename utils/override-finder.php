<?php
/*
 * Copyright (c) 2014-2016 Christophe Painchaud <shellescape _AT_ gmail.com>
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

print "***********************************************\n";
print "************ OVERRIDE-FINDER UTILITY ************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");

function display_usage_and_exit($shortMessage = false)
{
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=file.xml|api://... [more arguments]"."\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";
    print PH::boldText("\nExamples:\n");
    print " - php ".basename(__FILE__)." in=api://192.169.50.10 cycleConnectedFirewalls'\n";
    print " - php ".basename(__FILE__)." in=api://001C55663D@panorama-host\n";

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

    print "\n";
    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit(false);
}



print "\n";

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['cycleconnectedfirewalls'] = Array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides' );
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
    $debugAPI = true;
else
    $debugAPI = false;

if( isset(PH::$args['cycleconnectedfirewalls'])  )
    $cycleConnectedFirewalls = true;
else
    $cycleConnectedFirewalls = false;

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
    derr("Only API mode is supported, please provide an API input");
}
elseif ( $configInput['type'] == 'api'  )
{
    /** @var PanAPIConnector $inputConnector */
    $inputConnector = $configInput['connector'];

    if($debugAPI)
        $inputConnector->setShowApiCalls(true);
}
else
    derr('not supported yet');

function diffNodes(DOMElement $template, DOMElement $candidate, $padding)
{
    static $excludeXpathList = Array( '/config/devices/entry/deviceconfig/system/update-schedule/*/recurring'

    );

    if( $candidate->hasAttribute('src') && $candidate->getAttribute('src') == 'tpl' )
    {
        foreach( $template->childNodes as $templateNode )
        {
            if( $templateNode->nodeType != XML_ELEMENT_NODE )
                continue;

            /** @var DOMElement $templateNode */

            if( $templateNode->hasAttribute('name') )
                $candidateNode = DH::findFirstElementByNameAttrOrDie($templateNode->tagName, $templateNode->getAttribute('name'), $candidate);
            else
                $candidateNode = DH::findFirstElement($templateNode->tagName, $candidate);

            if( $candidateNode === FALSE )
            {
                $exclusionFound = false;
                foreach( $excludeXpathList as $excludeXPath )
                {
                    $xpathResults = DH::findXPath( '/config/template'.$excludeXPath, $template->ownerDocument);

                    foreach( $xpathResults as $searchNode )
                    {
                        /** @var DOMNode $searchNode */
                        if( $searchNode->isSameNode($template) )
                        {
                            $exclusionFound = true;
                            break;
                        }
                    }
                    if( $exclusionFound )
                        break;
                }


                if( $exclusionFound )
                {
                    print $padding."* ".DH::elementToPanXPath($candidate)."\n";
                }
                else
                    print $padding."* ".DH::elementToPanXPath($templateNode)." (defined in template but missing in Firewall config)\n";}
            else
                diffNodes($templateNode, $candidateNode, $padding);
        }
    }
    else
    {
        static $manualCheckXpathList = Array( '/config/mgt-config/users/entry/phash',
            '/config/shared/local-user-database/user/entry/phash',
            '/config/shared/certificate/entry/private-key'

        );

        $exclusionFound = false;
        foreach( $manualCheckXpathList as $excludeXPath )
        {
            $xpathResults = DH::findXPath('/config/template' . $excludeXPath, $template->ownerDocument);
            #$xpathResults = DH::findXPath( $excludeXPath, $template);

            foreach( $xpathResults as $searchNode )
            {
                /** @var DOMNode $searchNode */
                if( $searchNode->isSameNode($template) )
                {
                    $exclusionFound = TRUE;
                    break;
                }
            }
            if( $exclusionFound )
                break;
        }

        if( $exclusionFound )
        {
            if( $template->nodeValue != $candidate->nodeValue )
                $exclusionFound = FALSE;
        }

        if( $exclusionFound )
            return;

        if( $template->nodeValue == $candidate->nodeValue )
            $identicalText = '  (but same value as template)';
        else
            $identicalText = '';

        print $padding."* ".DH::elementToPanXPath($candidate)."{$identicalText}\n";
    }
}

/**
 * @param PanAPIConnector $apiConnector
 * @param string $padding
 */
function checkFirewallOverride($apiConnector, $padding)
{
    PH::enableExceptionSupport();
    print $padding." - Downloading candidate config...";
    $request = 'type=config&action=get&xpath=/config';

    try
    {
        $candidateDoc = $apiConnector->sendSimpleRequest($request);

        print "OK!\n";

        print $padding." - Looking for root /config xpath...";
        $configRoot = DH::findXPathSingleEntryOrDie('/response/result/config', $candidateDoc);
        print "OK!\n";

        DH::makeElementAsRoot($configRoot, $candidateDoc);

        print $padding." - Looking for root /config/template/config xpath...";
        $templateRoot = DH::findXPathSingleEntry('template/config', $configRoot);

        print "OK!\n";

        if( $templateRoot === FALSE )
        {
            echo $padding." - SKIPPED because no template applied!\n";
        }
        else
        {
            print "\n";

            print $padding . " ** Looking for overrides **\n";

            diffNodes($templateRoot, $configRoot, $padding);
        }
    }
    catch(Exception $e)
    {
        PH::disableExceptionSupport();
        print $padding." ***** an error occured : ".$e->getMessage()."\n\n";
        return;
    }

    PH::disableExceptionSupport();
}

if($cycleConnectedFirewalls)
{
    $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();

    $countFW = 0;
    foreach( $firewallSerials as $fw )
    {
        $countFW++;
        print " ** Handling FW #{$countFW}/".count($firewallSerials)." : serial/{$fw['serial']}   hostname/{$fw['hostname']} **\n";
        $tmpConnector = $inputConnector->cloneForPanoramaManagedDevice($fw['serial']);
        checkFirewallOverride($tmpConnector, '    ');
    }
}
else
{
    checkFirewallOverride($inputConnector, ' ');
}





print "\n************ DONE: OVERRIDE-FINDER UTILITY ************\n";
print   "*****************************************************";
print "\n\n";


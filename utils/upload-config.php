<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
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
print "************ UPLOAD CONFIG UTILITY ************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=file.xml|api://... out=file.xml|api://... [more arguments]\n";

    print PH::boldText("\nExamples:\n");
    print " - php ".basename(__FILE__)." help          : more help messages\n";
    print " - php ".basename(__FILE__)." in=api://192.169.50.10/running-config out=local.xml'\n";
    print " - php ".basename(__FILE__)." in=local.xml out=api://192.169.50.10 preserveMgmtsystem injectUserAdmin2\n";
    print " - php ".basename(__FILE__)." in=local.xml out=api://192.169.50.10 toXpath=/config/shared/address\n";

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
$extraFiltersOut = null;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['fromxpath'] = Array('niceName' => 'fromXpath', 'shortHelp' => 'select which part of the config to inject in destination');
$supportedArguments['toxpath'] = Array('niceName' => 'toXpath', 'shortHelp' => 'inject xml directly in some parts of the candidate config');
$supportedArguments['loadafterupload'] = Array('niceName' => 'loadAfterUpload', 'shortHelp' => 'load configuration after upload happened');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to answer, increase this value (default=60)');
$supportedArguments['preservemgmtconfig'] = Array('niceName' => 'preserveMgmtConfig', 'shortHelp' => "tries to preserve most of management settings like IP address, admins and passwords etc. note it's not a smart feature and may break your config a bit and requires manual fix in GUI before you can actually commit");
$supportedArguments['preservemgmtusers'] = Array('niceName' => 'preserveMgmtUsers', 'shortHelp' => "preserve administrators so they are not overwritten and you don't loose access after a commit");
$supportedArguments['preservemgmtsystem'] = Array('niceName' => 'preserveMgmtSystem', 'shortHelp' => 'preserves what is in /config/devices/entry/deviceconfig/system');
$supportedArguments['injectuseradmin2'] = Array('niceName' => 'injectUserAdmin2', 'shortHelp' => 'adds user "admin2" with password "admin" in administrators');
$supportedArguments['extrafiltersout'] = Array('niceName' => 'extraFiltersOut', 'shortHelp' => 'list of xpath separated by | character that will be stripped from the XML before going to output');


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


if( isset(PH::$args['debugapi'])  )
    $debugAPI = true;
else
    $debugAPI = false;

if( isset(PH::$args['loadafterupload']) )
{
    $loadConfigAfterUpload = true;
}

if( isset(PH::$args['fromxpath']) )
{
   if( !isset(PH::$args['toxpath']) )
   {
       display_error_usage_exit("'fromXpath' option must be used with 'toXpath'");
   }
    $fromXpath = PH::$args['fromxpath'];
    //$fromXpath = str_replace('"', "'", PH::$args['fromxpath']);
}
if( isset(PH::$args['toxpath']) )
{
    $toXpath = str_replace('"', "'", PH::$args['toxpath']);
}

if( !isset(PH::$args['apiTimeout']) )
    $apiTimeoutValue = 30;
else
    $apiTimeoutValue = PH::$args['apiTimeout'];

if( isset(PH::$args['extrafiltersout']) )
{
    $extraFiltersOut = explode('|', PH::$args['extrafiltersout']);
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
    print "{$configInput['filename']} ... ";
    $doc->Load($configInput['filename']);
}
elseif ( $configInput['type'] == 'api'  )
{
    if($debugAPI)
        $configInput['connector']->setShowApiCalls(true);

    print "{$configInput['connector']->apihost} ... ";

    /** @var PanAPIConnector $inputConnector */
    $inputConnector = $configInput['connector'];

    if( !isset($configInput['filename']) || $configInput['filename'] == '' || $configInput['filename'] == 'candidate-config' )
        $doc = $inputConnector->getCandidateConfig();
    elseif ( $configInput['filename'] == 'running-config' )
        $doc = $inputConnector->getRunningConfig();
    elseif ( $configInput['filename'] == 'merged-config' || $configInput['filename'] == 'merged' )
        $doc = $inputConnector->getMergedConfig();
    else
        $doc = $inputConnector->getSavedConfig($configInput['filename']);


}
else
    derr('not supported yet');

print " OK!!\n\n";


if( $extraFiltersOut !== null )
{
    print " * extraFiltersOut was specified and holds '".count($extraFiltersOut)." queries'\n";
        foreach( $extraFiltersOut as $filter )
        {
            print "  - processing XPath '''{$filter} ''' ";
            $xpathQ = new DOMXPath($doc);
            $results = $xpathQ->query($filter);

            if( $results->length == 0 )
                print " 0 results found!\n";
            else
            {
                print " {$results->length} matching nodes found!\n";
                foreach( $results as $node )
                {
                    /** @var DOMElement $node */
                    $panXpath = DH::elementToPanXPath($node);
                    print "     - deleting $panXpath\n";
                    $node->parentNode->removeChild($node);
                }

            }
            unset($xpathQ);
        }
    }


if( isset($fromXpath) )
{
    print " * fromXPath is specified with value '".$fromXpath."'\n";
    $foundInputXpathList = DH::findXPath($fromXpath, $doc);

    if( $foundInputXpathList === FALSE )
        derr("invalid xpath syntax");

    if( $foundInputXpathList->length == 0 )
        derr("xpath returned empty results");

    print "    * found ".$foundInputXpathList->length." results from Xpath:\n";

    foreach($foundInputXpathList as $xpath)
    {
        print "       - ".DH::elementToPanXPath($xpath)."\n";
    }

    print "\n";
}



//
// What kind of config output do we have.
//     File or API ?
//
$configOutput = PH::processIOMethod($configOutput, false);

if( $configOutput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configOutput['msg'] . "\n\n");exit(1);
}

if( $configOutput['type'] == 'file' )
{
    if( isset($toXpath) )
    {
        derr("toXpath options was used, it's incompatible with a file output. Make a feature request !!!  ;)");
    }
    print "Now saving configuration to ";
    print "{$configOutput['filename']}... ";
    $doc->save($configOutput['filename']);
    print "OK!\n";
}
elseif ( $configOutput['type'] == 'api'  )
{
    if( $debugAPI )
        $configOutput['connector']->setShowApiCalls(true);

    if( isset($toXpath) )
    {
        print "Sending SET command to API...";
        if( isset($toXpath) )
        {
            $stringToSend = '';
            foreach($foundInputXpathList as $xpath)
            {
                $stringToSend .= DH::dom_to_xml($xpath,-1, false);
            }
        }
        else
            $stringToSend = DH::dom_to_xml(DH::firstChildElement($doc),-1,false);

        $configOutput['connector']->sendSetRequest($toXpath, $stringToSend);
        print "OK!";
    }
    else
    {
        if (  isset(PH::$args['preservemgmtconfig']) ||
              isset(PH::$args['preservemgmtusers']) ||
            isset(PH::$args['preservemgmtsystem']))
        {
            print "Option 'preserveXXXXX was used, we will first download the running config of target device...";
            $runningConfig = $configOutput['connector']->getRunningConfig();
            print "OK!\n";

            $xpathQrunning = new DOMXPath($runningConfig);
            $xpathQlocal = new DOMXPath($doc);

            $xpathQueryList = Array();

            if (  isset(PH::$args['preservemgmtconfig']) ||
                isset(PH::$args['preservemgmtusers']) )
            {
                $xpathQueryList[] = '/config/mgt-config/users';
            }

            if (  isset(PH::$args['preservemgmtconfig']) ||
                isset(PH::$args['preservemgmtsystem']) )
            {
                $xpathQueryList[] = '/config/devices/entry/deviceconfig/system';
            }


            if (  isset(PH::$args['preservemgmtconfig']) )
            {
                $xpathQueryList[] = '/config/mgt-config';
                $xpathQueryList[] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig";
                $xpathQueryList[] = '/config/shared/authentication-profile';
                $xpathQueryList[] = '/config/shared/authentication-sequence';
                $xpathQueryList[] = '/config/shared/certificate';
                $xpathQueryList[] = '/config/shared/log-settings';
                $xpathQueryList[] = '/config/shared/local-user-database';
                $xpathQueryList[] = '/config/shared/admin-role';
            }

            foreach ($xpathQueryList as $xpathQuery)
            {
                $xpathResults = $xpathQrunning->query($xpathQuery);
                if ($xpathResults->length > 1)
                {
                    //var_dump($xpathResults);
                    derr('more than one one results found for xpath query: ' . $xpathQuery);
                }
                if ($xpathResults->length == 0)
                    $runningNodeFound = false;
                else
                    $runningNodeFound = true;

                $xpathResultsLocal = $xpathQlocal->query($xpathQuery);
                if ($xpathResultsLocal->length > 1)
                {
                    //var_dump($xpathResultsLocal);
                    derr('none or more than one one results found for xpath query: ' . $xpathQuery);
                }
                if ($xpathResultsLocal->length == 0)
                    $localNodeFound = false;
                else
                    $localNodeFound = true;

                if ($localNodeFound == false && $runningNodeFound == false)
                {
                    continue;
                }

                if ($localNodeFound && $runningNodeFound)
                {
                    $localParentNode = $xpathResultsLocal->item(0)->parentNode;
                    $localParentNode->removeChild($xpathResultsLocal->item(0));
                    $newNode = $doc->importNode($xpathResults->item(0), true);
                    $localParentNode->appendChild($newNode);
                    continue;
                }

                if ($localNodeFound == false && $runningNodeFound)
                {
                    $newXpath = explode('/', $xpathQuery);
                    if (count($newXpath) < 2)
                        derr('unsupported, debug xpath query: ' . $xpathQuery);

                    unset($newXpath[count($newXpath) - 1]);
                    $newXpath = implode('/', $newXpath);

                    $xpathResultsLocal = $xpathQlocal->query($newXpath);
                    if ($xpathResultsLocal->length != 1)
                    {
                        derr('unsupported, debug xpath query: ' . $newXpath);
                    }

                    $newNode = $doc->importNode($xpathResults->item(0), true);
                    $localParentNode = $xpathResultsLocal->item(0);
                    $localParentNode->appendChild($newNode);


                    continue;
                }

                //derr('unsupported');
            }

        }

        if( isset(PH::$args['injectuseradmin2']) )
        {
            $usersNode = DH::findXPathSingleEntryOrDie('/config/mgt-config/users', $doc);
            $newUserNode = DH::importXmlStringOrDie($doc, '<entry name="admin2"><phash>$1$bgnqjgob$HmenJzuuUAYmETzsMcdfJ/</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>');
            $usersNode->appendChild($newUserNode);
            print "Injected 'admin2' with 'admin' password\n";
        }

        if ($debugAPI)
            $configOutput['connector']->setShowApiCalls(true);

        if ($configOutput['filename'] !== null)
            $saveName = $configOutput['filename'];
        else
            $saveName = 'stage0.xml';

        print "Now saving/uploading that configuration to ";
        print "{$configOutput['connector']->apihost}/$saveName ... ";
        $configOutput['connector']->uploadConfiguration(DH::firstChildElement($doc), $saveName, false);
        print "OK!\n";
    }
}
else
    derr('not supported yet');



if( $loadConfigAfterUpload )
{
    print "Loading config in the firewall (will display warnings if any) ...\n";
    /** @var PanAPIConnector $targetConnector */
    $targetConnector = $configOutput['connector'];
    $xmlResponse = $targetConnector->sendCmdRequest('<load><config><from>' . $saveName . '</from></config></load>', true, 600);

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



print "\n************ DONE: UPLOAD CONFIG UTILITY ************\n";
print   "*****************************************************";
print "\n\n";





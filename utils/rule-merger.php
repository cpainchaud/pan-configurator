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


print "\n*************************************************\n";
print   "************ RULE-MERGER UTILITY ****************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml|api://... location=shared|sub [out=outputfile.xml]".
        " ['filter=(from has external) or (to has dmz)']\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";
    print PH::boldText("\nExamples:\n");
    print " - php ".basename(__FILE__)." in=api://192.169.50.10 location=DMZ-Firewall-Group\n";
    print " - php ".basename(__FILE__)." in=config.xml out=output.xml location=vsys1\n";

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

$debugAPI = false;
$configOutput = null;


$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments[] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes, API is not supported because it could be a heavy duty on management. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1');
$supportedArguments[] = Array('niceName' => 'Method', 'shortHelp' => 'rules will be merged if they match given a specific method, available methods are: ', 'argDesc' => '=method1');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = Array('niceName' => 'panoramaPreRules', 'shortHelp' => 'when using panorama, select pre-rulebase for merging');
$supportedArguments[] = Array('niceName' => 'panoramaPostRules', 'shortHelp' => 'when using panorama, select post-rulebase for merging');
$supportedArguments[] = Array('niceName' => 'mergeDenyRules', 'shortHelp' => 'deny rules wont be merged', 'argDesc' => '[yes|no|true|false]');
$supportedArguments[] = Array('niceName' => 'stopMergingIfDenySeen', 'shortHelp' => 'deny rules wont be merged', 'argDesc' => '[yes|no|true|false]');
$supportedArguments[] = Array('niceName' => 'mergeAdjacentOnly', 'shortHelp' => 'merge only rules that are adjacent to each other', 'argDesc' => '[yes|no|true|false]');
$supportedArguments[] = Array('niceName' => 'filter', 'shortHelp' => 'filter rules that can be converted');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$tmpArray = Array();
foreach($supportedArguments as &$arg)
{
    $tmpArray[strtolower($arg['niceName'])] = &$arg;
}
$supportedArguments = &$tmpArray;

//
//  methods array preparation
//
$supportedMethods_tmp = Array(  'matchFromToSrcDstApp'  => 1 ,
    'matchFromToSrcDstSvc'  => 2 ,
    'matchFromToSrcSvcApp'  => 3 ,
    'matchFromToDstSvcApp'  => 4 ,
    'matchFromSrcDstSvcApp' => 5 ,
    'matchToSrcDstSvcApp'   => 6 ,
    'matchToDstSvcApp'   => 7 ,
    'matchFromSrcSvcApp' => 8 ,
    'identical' => 9 ,
);
$supportedMethods = Array();
foreach( $supportedMethods_tmp as $methodName => $method )
{
    $supportedMethods[strtolower($methodName)] = $method;
}
$methodsNameList = array_flip($supportedMethods_tmp);
$supportedArguments['method']['shortHelp'] .= PH::list_to_string($methodsNameList);



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

//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >

$configInput = PH::processIOMethod($configInput, true);
$xmlDoc = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

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
    $xmlDoc = $configInput['connector']->getCandidateConfig();



    if( ! isset(PH::$args['out']) )
        display_error_usage_exit('"out" is missing from arguments. output file to save config after changes, API is not supported.');
    $configOutput = PH::$args['out'];
    if( !is_string($configOutput) || strlen($configOutput) < 1 )
        display_error_usage_exit('"out" argument is not a valid string');

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

$errorMessage = '';
$filterQuery = null;
if( isset(PH::$args['filter']) )
{
    $filterQuery = new RQuery('rule');
    if( ! $filterQuery->parseFromString(PH::$args['filter'], $errorMessage) )
        derr($errorMessage);
    print " - rule filter after sanitizing : ";
    $filterQuery->display();
}



//
// load the config
//
print " - loading config... ";
$pan->load_from_domxml($xmlDoc);
print "OK!\n";
// </editor-fold>



//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $rulesLocation = PH::$args['location'];
    if( !is_string($rulesLocation) || strlen($rulesLocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $pan->isFirewall() )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $rulesLocation = 'vsys1';
    }
    else
    {
        print " - No 'location' provided so using default ='shared'\n";
        $rulesLocation = 'shared';
    }
}

$panoramaPreRuleSelected = true;
if( $pan->isPanorama() )
{
    if( !isset(PH::$args[strtolower('panoramaPreRules')]) && !isset(PH::$args[strtolower('panoramaPostRules')]) )
        display_error_usage_exit("Panorama was detected but no Pre or Post rules were selected, use CLI argument 'panoramaPreRules' or 'panoramaPostRules'" );

    if( isset(PH::$args[strtolower('panoramaPreRules')]) && isset(PH::$args[strtolower('panoramaPostRules')]) )
        display_error_usage_exit("both panoramaPreRules and panoramaPostRules were selected, please choose one of them");

    if( isset(PH::$args[strtolower('panoramaPostRules')]) )
        $panoramaPreRuleSelected = false;

}


$processedLocation = null;

if( $pan->isPanorama() )
{
    if( $rulesLocation == 'shared' )
    {
        $processedLocation = $pan;
        if( $panoramaPreRuleSelected )
            $rulesToProcess = $pan->securityRules->preRules();
        else
            $rulesToProcess = $pan->securityRules->postRules();
    }
    else
    {
        $sub = $pan->findDeviceGroup($rulesLocation);
        if( $sub === null )
            derr("DeviceGroup named '{$rulesLocation}' not found");
        if( $panoramaPreRuleSelected )
            $rulesToProcess = $sub->securityRules->preRules();
        else
            $rulesToProcess = $sub->securityRules->postRules();

        $processedLocation = $sub;
    }
}
else
{
    $sub = $pan->findVirtualSystem($rulesLocation);
    if( $sub === null )
        derr("VirtualSystem named '{$rulesLocation}' not found");
    $rulesToProcess = $sub->securityRules->rules();
    $processedLocation = $sub;
}




if( !isset(PH::$args['method']) )
    display_error_usage_exit(' no method was provided');

$method = strtolower(PH::$args['method']);

if( !isset($supportedMethods[$method]) )
    display_error_usage_exit("unsupported method '".PH::$args['method']."' provided");

$method = $supportedMethods[$method];

if( !isset(PH::$args['mergedenyrules']) )
{
    print " - No 'mergeDenyRule' argument provided, using default 'no'\n";
    $mergeDenyRules = false;
}
else
{
    if( PH::$args['mergedenyrules'] === null || strlen(PH::$args['mergedenyrules']) == 0 )
        $mergeDenyRules = true;
    elseif(strtolower(PH::$args['mergedenyrules']) == 'yes' || strtolower(PH::$args['mergedenyrules']) == 'true')
        $mergeDenyRules = true;
    elseif(strtolower(PH::$args['mergedenyrules']) == 'no' || strtolower(PH::$args['mergedenyrules']) == 'false')
        $mergeDenyRules = false;
    else
        display_error_usage_exit("'mergeDenyRules' argument was given unsupported value '".PH::$args['mergedenyrules']."'");
}

if( !isset(PH::$args['stopmergingifdenyseen']) )
{
    print " - No 'stopMergingIfDenySeen' argument provided, using default 'yes'\n";
    $stopMergingIfDenySeen = true;
}
else
{
    if( PH::$args['stopmergingifdenyseen'] === null || strlen(PH::$args['stopmergingifdenyseen']) == 0 )
            $stopMergingIfDenySeen = true;
    elseif(strtolower(PH::$args['stopmergingifdenyseen']) == 'yes'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 'true'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 1 )
            $stopMergingIfDenySeen = true;
    elseif(strtolower(PH::$args['stopmergingifdenyseen']) == 'no'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 'false'
        || strtolower(PH::$args['stopmergingifdenyseen']) == 0 )
            $stopMergingIfDenySeen = false;
    else
        display_error_usage_exit("'stopMergingIfDenySeen' argument was given unsupported value '".PH::$args['stopmergingifdenyseen']."'");
}

if( !isset(PH::$args['mergeadjacentonly']) )
{
    print " - No 'mergeAdjacentOnly' argument provided, using default 'no'\n";
    $mergeAdjacentOnly = false;
}
else
{
    if( PH::$args['mergeadjacentonly'] === null || strlen(PH::$args['mergeadjacentonly']) == 0 )
        $mergeAdjacentOnly = true;

    elseif(strtolower(PH::$args['mergeadjacentonly']) == 'yes'
        || strtolower(PH::$args['mergeadjacentonly']) == 'true'
        || strtolower(PH::$args['mergeadjacentonly']) == 1 )

        $mergeAdjacentOnly = true;

    elseif(strtolower(PH::$args['mergeadjacentonly']) == 'no'
        || strtolower(PH::$args['mergeadjacentonly']) == 'false'
        || strtolower(PH::$args['mergeadjacentonly']) == 0 )

        $mergeAdjacentOnly = false;
    else
        display_error_usage_exit("(mergeAdjacentOnly' argument was given unsupported value '".PH::$args['mergeadjacentonly']."'");
    print " - mergeAdjacentOnly = ".boolYesNo($mergeAdjacentOnly)."\n";
}



$hashTable = Array();

/**
 * @param $rule SecurityRule
 * @param $method
 * @throws Exception
 */
function updateRuleHash($rule, $method)
{
    global $hashTable;

    if( isset($rule->mergeHash) )
    {
        if( isset($hashTable[$rule->mergeHash]) )
        {
            if( isset($hashTable[$rule->mergeHash][$rule->serial]) )
            {
                unset($hashTable[$rule->mergeHash][$rule->serial]);
            }
        }
    }

    /*          'matchFromToSrcDstApp'  => 1 ,
                'matchFromToSrcDstSvc'  => 2 ,
                'matchFromToSrcSvcApp'  => 3 ,
                'matchFromToDstSvcApp'  => 4 ,
                'matchFromSrcDstSvcApp' => 5 ,
                'matchToSrcDstSvcApp'   => 6 ,
                'matchToDstSvcApp'   => 7 ,
                'matchFromSrcSvcApp' => 8 ,
                identical' => 9 ,
    */

    if( $method == 1)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
            $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
            $rule->apps->getFastHashComp(), true);
    elseif( $method == 2)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
            $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
            $rule->services->getFastHashComp(), true);
    elseif( $method == 3)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
            $rule->source->getFastHashComp() .
            $rule->services->getFastHashComp() . $rule->apps->getFastHashComp(), true);
    elseif( $method == 4)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
            $rule->destination->getFastHashComp() .
            $rule->services->getFastHashComp() . $rule->apps->getFastHashComp(), true);
    elseif( $method == 5)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->from->getFastHashComp() .
            $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
            $rule->services->getFastHashComp() . $rule->apps->getFastHashComp(), true);
    elseif( $method == 6)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->to->getFastHashComp() .
            $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
            $rule->services->getFastHashComp() . $rule->apps->getFastHashComp(), true);
    elseif( $method == 7)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->to->getFastHashComp() .
            $rule->destination->getFastHashComp() .
            $rule->services->getFastHashComp() . $rule->apps->getFastHashComp(), true);
    elseif( $method == 8)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->from->getFastHashComp() .
            $rule->source->getFastHashComp() .
            $rule->services->getFastHashComp() . $rule->apps->getFastHashComp(), true);
    elseif( $method == 9)
        $rule->mergeHash = md5('action:'.$rule->action().'.*/' . $rule->from->getFastHashComp() . $rule->to->getFastHashComp() .
            $rule->source->getFastHashComp() . $rule->destination->getFastHashComp() .
            $rule->services->getFastHashComp() .
            $rule->apps->getFastHashComp(), true);
    else
        derr("unsupported method #$method");

    $hashTable[$rule->mergeHash][$rule->serial] = $rule;
}

/**
 * @param $rule SecurityRule
 * @param $ruleToMerge SecurityRule
 * @param $method int
 * @throws Exception
 */
function mergeRules( $rule, $ruleToMerge, $method )
{
    global $configInput;
    global $configOutput;
    global $hashTable;

    /*          'matchFromToSrcDstApp'  => 1 ,
                                'matchFromToSrcDstSvc'  => 2 ,
                                'matchFromToSrcSvcApp'  => 3 ,
                                'matchFromToDstSvcApp'  => 4 ,
                                'matchFromSrcDstSvcApp' => 5 ,
                                'matchToSrcDstSvcApp'   => 6 ,
                                'matchToDstSvcApp'   => 7 ,
                                'matchFromSrcSvcApp' => 8 ,
                                'matchFromSrcSvcApp' => 9 ,

    */



    if( $method == 1)
    {
        $rule->services->merge($ruleToMerge->services);
    }
    elseif( $method == 2)
    {
        $rule->apps->merge($ruleToMerge->apps);
    }
    elseif( $method == 3)
    {
        $rule->destination->merge($ruleToMerge->destination);
    }
    elseif( $method == 4)
    {
        $rule->source->merge($ruleToMerge->source);
    }
    elseif( $method == 5)
    {
        $rule->to->merge($ruleToMerge->to);
    }
    elseif( $method == 6)
    {
        $rule->from->merge($ruleToMerge->from);
    }
    elseif( $method == 7)
    {
        $rule->from->merge($ruleToMerge->from);
        $rule->source->merge($ruleToMerge->source);
    }
    elseif( $method == 8)
    {
        $rule->to->merge($ruleToMerge->to);
        $rule->destination->merge($ruleToMerge->destination);
    }
    elseif( $method == 9)
    {
        //
    }
    else
        derr("unsupported method #$method");

    // clean this rule from hash table
    unset($hashTable[$ruleToMerge->mergeHash][$rule->serial]);
    if ( $configInput['type'] == 'api' && $configOutput == null )
        $ruleToMerge->owner->API_remove( $ruleToMerge );
    else
        $ruleToMerge->owner->remove($ruleToMerge);
    $ruleToMerge->alreadyMerged = true;

    //updateRuleHash($rule, $method);
}

/** @var SecurityRule[] $denyRules */
$denyRules = Array();

print " - Calculating all rules hash, please be patient... ";
foreach( array_keys($rulesToProcess) as $index)
{
    $rule = $rulesToProcess[$index];

    if( $rule->isDisabled() )
    {
        unset($rulesToProcess[$index]);
        continue;
    }

    $rule->serial = spl_object_hash($rule);
    $rule->indexPosition = $index;

    updateRuleHash($rule, $method);

    if( $stopMergingIfDenySeen && $rule->actionIsNegative())
    {
        $denyRules[] = $rule;
    }
}
print "OK!\n";




print "\nStats before merging :\n";
$processedLocation->display_statistics();

print "\n**** NOW STARTING TO MERGE RULES\n";


$loopCount = -1;
$rulesArrayIndex = array_flip(array_keys($rulesToProcess));
$mergedRulesCount = 0;

/**
 * @param $rule SecurityRule
 * @return bool
 */
function findNearestDenyRule($rule)
{
    global $denyRules;
    global $rulesToProcess;
    global $rulesArrayIndex;

    $foundRule = false;

    $rulePosition = $rulesArrayIndex[$rule->indexPosition];

    foreach( $denyRules as $index => $denyRule )
    {
        //var_dump($rulesArrayIndex);
        $denyRulePosition = $rulesArrayIndex[$denyRule->indexPosition];
        if( $rulePosition < $denyRulePosition )
        {
            return $denyRule;
        }
        else
            unset($denyRules[$index]);
    }

    return $foundRule;
}

foreach( $rulesToProcess as $index => $rule )
{
    $loopCount++;

    if( isset($rule->alreadyMerged) )
        continue;

    if( $rule->actionIsNegative() )
        continue;

    if( $filterQuery !== null && ! $filterQuery->matchSingleObject($rule) )
        continue;

    print "\n";

    /** @var SecurityRule[] $matchingHashTable */
    $matchingHashTable = $hashTable[$rule->mergeHash];

    $rulePosition = $rulesArrayIndex[$rule->indexPosition];

    // clean already merged rules
    foreach( $matchingHashTable as $ruleToCompare )
    {
        if( isset($ruleToCompare->alreadyMerged) )
            unset($matchingHashTable[$ruleToCompare->serial]);
    }

    if( count($matchingHashTable) == 1 )
    {
        print "- no match for rule #$loopCount '{$rule->name()}''\n";
        continue;
    }

    print "- Processing rule #$loopCount\n";
    $rule->display(4);

    $nextDenyRule = false;
    if( $stopMergingIfDenySeen )
    {
        $nextDenyRule = findNearestDenyRule($rule);
        if( $nextDenyRule !== false )
            $nextDenyRulePosition = $rulesArrayIndex[$nextDenyRule->indexPosition];
    }

    // ignore rules that are placed before this one
    unset($matchingHashTable[$rule->serial]);

    $adjacencyPositionReference = $rulePosition;
    foreach( $matchingHashTable as $ruleToCompare )
    {
        $ruleToComparePosition = $rulesArrayIndex[$ruleToCompare->indexPosition];
        if( $loopCount > $ruleToComparePosition )
        {
            unset($matchingHashTable[$ruleToCompare->serial]);
            print "    - ignoring rule #{$ruleToComparePosition} '{$ruleToCompare->name()}' because it's placed before\n";
        }
        else if( $nextDenyRule !== false && $nextDenyRulePosition < $ruleToComparePosition  )
        {
            unset($matchingHashTable[$ruleToCompare->serial]);
            print "    - ignoring rule #{$ruleToComparePosition} '{$ruleToCompare->name()}' because DENY rule #{$nextDenyRulePosition} '{$nextDenyRule->name()}' is placed before\n";
        }
        elseif( $filterQuery !== null && ! $filterQuery->matchSingleObject($ruleToCompare) )
        {
            unset($matchingHashTable[$ruleToCompare->serial]);
            print "    - ignoring rule #{$ruleToComparePosition} '{$ruleToCompare->name()}' because it's not matchin the filter query\n";
        }
    }

    if( count($matchingHashTable) == 0 )
    {
        print "    - no more rules to match with\n";
        unset($hashTable[$rule->mergeHash][$rule->serial]);
        continue;
    }

    $adjacencyPositionReference = $rulePosition;


    print "       - Now merging with the following ".count($matchingHashTable)." rules:\n";

    foreach($matchingHashTable as $ruleToCompare)
    {
        if ($mergeAdjacentOnly)
        {
            $ruleToComparePosition = $rulesArrayIndex[$ruleToCompare->indexPosition];
            $adjacencyPositionDiff = $ruleToComparePosition - $adjacencyPositionReference;
            if ($adjacencyPositionDiff < 1)
                derr('an unexpected event occured');

            if( $adjacencyPositionDiff > 1 )
            {
                print "    - ignored '{$ruleToCompare->name()}' because of option 'mergeAdjacentOnly'\n";
                break;
            }
            //print "    - adjacencyDiff={$adjacencyPositionDiff}\n";

            $adjacencyPositionReference = $ruleToComparePosition;
        }
        if( $method == 1 )
        {
            // merging on services requires extra checks for application-default vs non app default
            if( $rule->services->isApplicationDefault() )
            {
                if( ! $ruleToCompare->services->isApplicationDefault() )
                {
                    print "    - ignored '{$ruleToCompare->name()}' because it is not Application-Default\n";
                    break;
                }
            }
            else
            {
                if( $ruleToCompare->services->isApplicationDefault() )
                {
                    print "    - ignored '{$ruleToCompare->name()}' because it is Application-Default\n";
                    break;
                }
            }
        }

        $ruleToCompare->display(9);
        mergeRules($rule, $ruleToCompare, $method);
        $mergedRulesCount++;
    }

    print "    - Rule after merge:\n";
    $rule->display(5);

    if ( $configInput['type'] == 'api' && $configOutput == null )
        $rule->API_sync();
    unset($hashTable[$rule->mergeHash][$rule->serial]);

}

print "\n*** MERGING DONE : {$mergedRulesCount} rules merged over ".count($rulesToProcess)." in total (".(count($rulesToProcess)-$mergedRulesCount)." remaining) ***\n";
print "\nStats after merging :\n";
$processedLocation->display_statistics();

// save our work !!!
if( $configOutput !== null )
{
    print " - saving final config to $configOutput... ";
    $pan->save_to_file($configOutput, false);
    print "OK!\n";
}





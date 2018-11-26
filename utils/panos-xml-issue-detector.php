<?php

print "\n*********** START OF SCRIPT ".basename(__FILE__)." ************\n\n";

// load PAN-Configurator library
require_once("lib/panconfigurator.php");

PH::processCliArgs();

$configInput = null;
$configOutput = null;


if( !isset(PH::$args['in']) )
    derr("missing 'in' argument");


if(isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if (!is_string($configOutput) || strlen($configOutput) < 1)
        derr('"out" argument is not a valid string');
}
else
    derr('"out" is missing from arguments');

if( isset(PH::$args['debugapi'])  )
    $debugAPI = true;
else
    $debugAPI = false;

$configInput = PH::processIOMethod(PH::$args['in'], true);
if( $configInput['status'] == 'fail' )
    derr($configInput['msg']);


$apiMode = false;

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc = new DOMDocument();
    if( ! $xmlDoc->load($configInput['filename'], 4194304) )
        derr("error while reading xml config file");

}
elseif ( $configInput['type'] == 'api'  )
{
    $apiMode = true;
    /** @var PanAPIConnector $connector */
    $connector = $configInput['connector'];
    if($debugAPI)
        $connector->setShowApiCalls(true);
    print " - Downloading config from API... ";
    $xmlDoc = $connector->getRunningConfig();
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

print " - Detected platform type is '{$configType}'\n";



///////////////////////////////////////////////////////////
//clean stage config / delete all <deleted> entries
$xpath = new DOMXpath($xmlDoc);

// example 1: for everything with an id
$elements = $xpath->query("//deleted");


foreach( $elements as $element )
{
    $element->parentNode->removeChild($element);
}
///////////////////////////////////////////////////////////


//
// REAL JOB STARTS HERE
//
//

$totalAddressGroupsFixed = 0;
$totalServiceGroupsFixed = 0;

$totalAddressGroupsSubGroupFixed = 0;
$totalServiceGroupsSubGroupFixed = 0;

$countDuplicateAddressObjects = 0;
$countDuplicateServiceObjects = 0;

$countMissconfiguredAddressObjects = 0;
$countMissconfiguredServiceObjects = 0;
$countEmptyAddressGroup = 0;
$countEmptyServiceGroup = 0;


/** @var DOMElement[] $locationNodes */
$locationNodes['shared'] = DH::findXPathSingleEntryOrDie('/config/shared', $xmlDoc);

if( $configType == 'panos')
    $tmpNodes = DH::findXPath('/config/devices/entry/vsys/entry', $xmlDoc);
else
    $tmpNodes = DH::findXPath('/config/devices/entry/device-group/entry', $xmlDoc);


foreach($tmpNodes as $node)
    $locationNodes[$node->getAttribute('name')] = $node;

print " - Found ".count($locationNodes)." locations (VSYS/DG)\n";

print "\n *******   ********   ********\n\n";

foreach( $locationNodes as $locationName => $locationNode)
{
    print "\n** PARSING VSYS/DG '{$locationName}' **\n";

    $addressObjects = Array();
    $addressGroups = Array();
    $addressIndex = Array();

    $serviceObjects = Array();
    $serviceGroups = Array();
    $serviceIndex = Array();

    $zoneObjects = Array();
    $zoneIndex = Array();


    $objectTypeNode = DH::findFirstElement('address', $locationNode);
    if( $objectTypeNode !== false )
    {
        foreach( $objectTypeNode->childNodes as $objectNode )
        {
            /** @var DOMElement $objectNode */
            if( $objectNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectName = $objectNode->getAttribute('name');


            $addressObjects[$objectName][] = $objectNode;

            if( !isset($addressIndex[$objectName]) )
                $addressIndex[$objectName] = Array( 'regular' => Array(), 'group' => Array());

            $addressIndex[$objectName]['regular'][] = $objectNode;
        }

    }

    $objectTypeNode = DH::findFirstElement('address-group', $locationNode);
    if( $objectTypeNode !== false )
    {
        foreach( $objectTypeNode->childNodes as $objectNode )
        {
            /** @var DOMElement $objectNode */
            if( $objectNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectName = $objectNode->getAttribute('name');


            $addressGroups[$objectName][] = $objectNode;

            if( !isset($addressIndex[$objectName]) )
                $addressIndex[$objectName] = Array( 'regular' => Array(), 'group' => Array());

            $addressIndex[$objectName]['group'][] = $objectNode;
        }
    }


    print "\n\n";
    print "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####\n";
    print " - parsed ".count($addressObjects)." address objects and ".count($addressGroups)." groups\n";
    print "\n";

    //
    //
    //
    print "\n - Scanning for address with missing IP-netmask/IP-range/FQDN information...\n";
    foreach($addressObjects as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $ip_netmaskNode = DH::findFirstElement('ip-netmask', $node);
            $ip_rangeNode = DH::findFirstElement('ip-range', $node);
            $fqdnNode = DH::findFirstElement('fqdn', $node);
            if( $ip_netmaskNode === FALSE && $ip_rangeNode === FALSE && $fqdnNode === FALSE )
            {
                echo "    - address object '{$objectName}' from DG/VSYS {$locationName} has missing IP configuration ... (*FIX_MANUALLY*)\n";
                print "       - type 'Address' at XML line #{$node->getLineNo()}\n";
                $countMissconfiguredAddressObjects++;
            }
        }
    }

    //
    //
    //
    print "\n - Scanning for address groups with empty members...\n";
    foreach($addressGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('static', $node);
            if( $staticNode === FALSE )
            {
                echo "    - addressgroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)\n";
                print "       - type 'AddressGroup' at XML line #{$node->getLineNo()}\n";
                $countEmptyAddressGroup++;
            }
        }
    }


    //
    //
    //
    print "\n - Scanning for address groups with duplicate members...\n";
    foreach($addressGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('static', $node);
            if( $staticNode === FALSE )
                continue;

            $membersIndex = Array();
            /** @var DOMElement[] $nodesToRemove */
            $nodesToRemove = Array();

            foreach($staticNode->childNodes as $staticNodeMember)
            {
                /** @var DOMElement $staticNodeMember */
                if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                    continue;

                $memberName = $staticNodeMember->textContent;

                if( isset($membersIndex[$memberName]) )
                {
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*\n";
                    $nodesToRemove[] = $staticNodeMember;
                    $totalAddressGroupsFixed++;
                    continue;
                }

                $membersIndex[$memberName] = true;
            }

            foreach($nodesToRemove as $nodeToRemove)
                $nodeToRemove->parentNode->removeChild($nodeToRemove);
        }
    }

    //
    //
    //
    print "\n - Scanning for address groups with own membership as subgroup...\n";
    foreach($addressGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('static', $node);
            if( $staticNode === FALSE )
                continue;

            $membersIndex = Array();
            /** @var DOMElement[] $nodesToRemove */
            $nodesToRemove = Array();

            foreach($staticNode->childNodes as $staticNodeMember)
            {
                /** @var DOMElement $staticNodeMember */
                if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                    continue;

                $memberName = $staticNodeMember->textContent;

                if( $objectName == $memberName )
                {
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*\n";
                    $staticNodeMember->parentNode->removeChild($staticNodeMember);
                    $totalAddressGroupsSubGroupFixed++;
                    continue;
                }
            }
        }
    }


    //
    //
    //
    print "\n - Scanning for duplicate address objects...\n";
    foreach($addressIndex as $objectName => $objectNodes )
    {
        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

        if( $dupCount < 2 )
            continue;

        print "   - found address object named '{$objectName}' that exists ".$dupCount." time (*FIX_MANUALLY*):\n";

        $tmp_addr_array = array();
        foreach( $objectNodes['regular'] as $objectNode )
        {
            $ip_netmaskNode = DH::findFirstElement('ip-netmask', $objectNode);
            if( $ip_netmaskNode === FALSE )
                continue;

            /** @var DOMElement $objectNode */
            print "       - type 'Address' value: '".$ip_netmaskNode->nodeValue."' at XML line #{$objectNode->getLineNo()}";

            //Todo: check if address object value is same, then delete it
            //TODO: VALIDATION needed if working as expected

            if( !isset($tmp_addr_array[$ip_netmaskNode->nodeValue]) )
                $tmp_addr_array[$ip_netmaskNode->nodeValue] = $ip_netmaskNode->nodeValue;
            else
            {
                $objectNode->parentNode->removeChild( $objectNode );
                print PH::boldText(" (removed)");
                $countDuplicateAddressObjects--;
            }
            
            print "\n";

            $countDuplicateAddressObjects++;
        }

        $tmp_srv_array = array();
        foreach( $objectNodes['group'] as $objectNode )
        {
            #print_r($objectNodes['group']);
            $protocolNode = DH::findFirstElement('static', $objectNode);
            if( $protocolNode === FALSE )
                continue;

            $txt = "";
            foreach( $protocolNode->childNodes as $member )
            {
                /** @var DOMElement $objectNode */
                if( $member->nodeType != XML_ELEMENT_NODE )
                    continue;

                $txt .= $member->nodeValue;
            }
            //print "|".$txt."|\n";

            /** @var DOMElement $objectNode */
            print "       - type 'AddressGroup' at XML line #{$objectNode->getLineNo()}";

            //Todo: check if servicegroup object value is same, then delete it
            //TODO: VALIDATION needed if working as expected

            if( !isset($tmp_srv_array[$txt]) )
                $tmp_srv_array[$txt] = $txt;
            else
            {
                $objectNode->parentNode->removeChild( $objectNode );
                print PH::boldText(" (removed)");
                $countDuplicateAddressObjects--;
            }
            print "\n";


            $countDuplicateAddressObjects++;
        }
        #$countDuplicateAddressObjects--;
    }


    //
    //
    //
    //
    //
    //

    $objectTypeNode = DH::findFirstElement('service', $locationNode);
    if( $objectTypeNode !== false )
    {
        foreach( $objectTypeNode->childNodes as $objectNode )
        {
            /** @var DOMElement $objectNode */
            if( $objectNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectName = $objectNode->getAttribute('name');

            $serviceObjects[$objectName][] = $objectNode;

            if( !isset($serviceIndex[$objectName]) )
                $serviceIndex[$objectName] = Array('regular' => Array(), 'group' => Array());

            $serviceIndex[$objectName]['regular'][] = $objectNode;
        }

    }

    $objectTypeNode = DH::findFirstElement('service-group', $locationNode);
    if( $objectTypeNode !== false )
    {
        foreach( $objectTypeNode->childNodes as $objectNode )
        {
            /** @var DOMElement $objectNode */
            if( $objectNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectName = $objectNode->getAttribute('name');


            $serviceGroups[$objectName][] = $objectNode;

            if( !isset($serviceIndex[$objectName]) )
                $serviceIndex[$objectName] = Array('regular' => Array(), 'group' => Array());

            $serviceIndex[$objectName]['group'][] = $objectNode;
        }
    }

    print "\n\n";
    print "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####\n";
    print " - parsed ".count($serviceObjects)." service objects and ".count($serviceGroups)." groups\n";
    print "\n";

    //
    //
    //
    print "\n - Scanning for service with missing protocol information...\n";
    foreach($serviceObjects as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $protocolNode = DH::findFirstElement('protocol', $node);
            if( $protocolNode === FALSE  )
            {
                echo "    - serivce object '{$objectName}' from DG/VSYS {$locationName} has missing protocol configuration ... (*FIX_MANUALLY*)\n";
                print "       - type 'Service' at XML line #{$node->getLineNo()}\n";
                $countMissconfiguredServiceObjects++;
            }
        }
    }

    //
    //
    //
    print "\n - Scanning for service groups with empty members...\n";
    foreach($serviceGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('members', $node);
            if( $staticNode === FALSE )
            {
                echo "    - servicegroup object '{$objectName}' from DG/VSYS {$locationName} has no member ... (*FIX_MANUALLY*)\n";
                print "       - type 'ServiceGroup' at XML line #{$node->getLineNo()}\n";
                $countEmptyServiceGroup++;
            }
        }
    }

    print "\n - Scanning for service groups with duplicate members...\n";
    foreach($serviceGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('members', $node);
            if( $staticNode === FALSE )
                continue;

            $membersIndex = Array();
            /** @var DOMElement[] $nodesToRemove */
            $nodesToRemove = Array();

            foreach($staticNode->childNodes as $staticNodeMember)
            {
                /** @var DOMElement $staticNodeMember */
                if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                    continue;

                $memberName = $staticNodeMember->textContent;

                if( isset($membersIndex[$memberName]) )
                {
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has a duplicate member named '{$memberName}' ... *FIXED*\n";
                    $nodesToRemove[] = $staticNodeMember;
                    $totalServiceGroupsFixed++;
                    continue;
                }

                $membersIndex[$memberName] = true;
            }

            foreach($nodesToRemove as $nodeToRemove)
                $nodeToRemove->parentNode->removeChild($nodeToRemove);
        }
    }


    //
    //
    //
    print "\n - Scanning for service groups with own membership as subgroup...\n";
    foreach($serviceGroups as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $staticNode = DH::findFirstElement('members', $node);
            if( $staticNode === FALSE )
                continue;

            $membersIndex = Array();
            /** @var DOMElement[] $nodesToRemove */
            $nodesToRemove = Array();

            foreach($staticNode->childNodes as $staticNodeMember)
            {
                /** @var DOMElement $staticNodeMember */
                if( $staticNodeMember->nodeType != XML_ELEMENT_NODE )
                    continue;

                $memberName = $staticNodeMember->textContent;

                if( $objectName == $memberName )
                {
                    echo "    - group '{$objectName}' from DG/VSYS {$locationName} has itself as member '{$memberName}' ... *FIXED*\n";
                    $staticNodeMember->parentNode->removeChild($staticNodeMember);
                    $totalServiceGroupsSubGroupFixed++;
                    continue;
                }
            }
        }
    }


    print "\n - Scanning for duplicate service objects...\n";
    foreach($serviceIndex as $objectName => $objectNodes )
    {
        $dupCount = count($objectNodes['regular']) + count($objectNodes['group']);

        if( $dupCount < 2 )
            continue;

        print "   - found service object named '{$objectName}' that exists ".$dupCount." time (*FIX_MANUALLY*):\n";
        $tmp_srv_array = array();
        foreach( $objectNodes['regular'] as $objectNode )
        {
            $protocolNode = DH::findFirstElement('protocol', $objectNode);
            if( $protocolNode === FALSE )
                continue;

            /** @var DOMElement $objectNode */
            print "       - type 'Service' value: '".$protocolNode->nodeValue."' at XML line #{$objectNode->getLineNo()}";

            //Todo: check if service object value is same, then delete it
            //TODO: VALIDATION needed if working as expected

            if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
            else
            {
                $objectNode->parentNode->removeChild( $objectNode );
                print PH::boldText(" (removed)");
                $countDuplicateServiceObjects--;
            }
            print "\n";

            $countDuplicateServiceObjects++;
        }

        $tmp_srv_array = array();
        foreach( $objectNodes['group'] as $objectNode )
        {
            $protocolNode = DH::findFirstElement('members', $objectNode);
            if( $protocolNode === FALSE )
                continue;


            /** @var DOMElement $objectNode */
            print "       - type 'ServiceGroup' at XML line #{$objectNode->getLineNo()}";

            //Todo: check if servicegroup object value is same, then delete it
            //TODO: VALIDATION needed if working as expected

            if( !isset($tmp_srv_array[$protocolNode->nodeValue]) )
                $tmp_srv_array[$protocolNode->nodeValue] = $protocolNode->nodeValue;
            else
            {
                $objectNode->parentNode->removeChild( $objectNode );
                print PH::boldText(" (removed)");
                $countDuplicateServiceObjects--;
            }
            print "\n";

            $countDuplicateServiceObjects++;
        }
        #$countDuplicateServiceObjects--;
    }


    $objectTypeNode = DH::findFirstElement('zone', $locationNode);
    if( $objectTypeNode !== false )
    {
        foreach( $objectTypeNode->childNodes as $objectNode )
        {
            /** @var DOMElement $objectNode */
            if( $objectNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $objectName = $objectNode->getAttribute('name');

            $zoneObjects[$objectName][] = $objectNode;

            if( !isset($zoneIndex[$objectName]) )
                $zoneIndex[$objectName] = Array( 'regular' => Array(), 'group' => Array());

            $zoneIndex[$objectName]['regular'][] = $objectNode;
        }

    }

    print "\n\n";
    print "#####     #####     #####     #####     #####     #####     #####     #####     #####     #####     #####\n";
    print " - parsed ".count($zoneObjects)." zone objects \n";
    print "\n";

    //
    //
    //
    print "\n - Scanning for zones with wrong zone type (e.g. Layer3 instead of layer3 - case sensitive - Expedition issue?)...\n";
    foreach($zoneObjects as $objectName => $nodes )
    {
        foreach( $nodes as $node )
        {
            $zone_network = DH::findFirstElement('network', $node);

            foreach( $zone_network->childNodes as $key => $zone_type )
            {
                /** @var DOMElement $objectNode */
                if( $zone_type->nodeType != XML_ELEMENT_NODE )
                    continue;

                $str = $zone_type->nodeName;

                if( preg_match_all('/[A-Z][^A-Z]*/',$str,$results) )
                {
                    if( isset( $results[0][0] ) )
                    {
                        print "       - type 'Zone' name: '".$node->getAttribute('name')."' - '".$results[0][0]."' at XML line #{$zone_type->getLineNo()} (*FIX_MANUALLY*)\n" ;

                    }

                }



            }
        }
    }

    print "\n** ** ** ** ** ** **\n";
}


echo "\nSummary:\n";
echo " - FIXED: duplicate address-group members: {$totalAddressGroupsFixed}\n";
echo " - FIXED: duplicate service-group members: {$totalServiceGroupsFixed}\n";
echo " - FIXED: own address-group as subgroup member: {$totalAddressGroupsSubGroupFixed}\n";
echo " - FIXED: own service-group as subgroup members: {$totalServiceGroupsSubGroupFixed}\n";
echo "\n\nIssues that could not be fixed (look in logs for FIX_MANUALLY keyword):\n";
echo " - FIX_MANUALLY: duplicate address objects: {$countDuplicateAddressObjects} (look in the logs )\n";
echo " - FIX_MANUALLY: duplicate service objects: {$countDuplicateServiceObjects} (look in the logs)\n\n";
echo " - FIX_MANUALLY: missconfigured address objects: {$countMissconfiguredAddressObjects} (look in the logs)\n";
echo " - FIX_MANUALLY: empty address-group: {$countEmptyAddressGroup} (look in the logs)\n\n";
echo " - FIX_MANUALLY: missconfigured service objects: {$countMissconfiguredServiceObjects} (look in the logs)\n";
echo " - FIX_MANUALLY: empty service-group: {$countEmptyServiceGroup} (look in the logs)\n";

if ( $configInput['type'] == 'api'  )
    echo "\n\nINPUT mode API detected: FIX is ONLY saved in offline file.\n";


// save our work !!!
if( $configOutput !== null )
{
    echo "\n\nSaving to file: ".PH::$args['out']."\n";
    if( $configOutput != '/dev/null' )
    {
        $xmlDoc->save(PH::$args['out']);
    }
}


print "\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";


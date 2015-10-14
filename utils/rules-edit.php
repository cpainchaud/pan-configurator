<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
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


print "\n***********************************************\n";
print "************ RULE-EDIT UTILITY ****************\n\n";

set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");
require_once("common/actions.php");


function display_usage_and_exit($shortMessage = false)
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=inputfile.xml out=outputfile.xml location=all|shared|sub ".
        "actions=action1:arg1 ['filter=(from has external) or (to has dmz)']\n";
    print "php ".basename(__FILE__)." listactions   : list supported actions\n";
    print "php ".basename(__FILE__)." listfilters   : list supported filter\n";
    print "php ".basename(__FILE__)." help          : more help messages\n";
    print PH::boldText("\nExamples:\n");
    print " - php ".basename(__FILE__)." in=api://192.169.50.10 location=DMZ-Firewall-Group actions=from-add:dmz2,dmz3 'filter=(to has untrust) or (to is.any)'\n";
    print " - php ".basename(__FILE__)." in=config.xml out=output.xml location=any actions=setSecurityProfile:avProf1\n";

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
$rulesLocation = 'shared';
$rulesFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['ruletype'] = Array('niceName' => 'ruleType', 'shortHelp' => 'specify which type(s) of you rule want to edit, (default is "security". ie: ruletype=any  ruletype=security,nat', 'argDesc' => 'all|any|security|nat|decryption');
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['listactions'] = Array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
$supportedArguments['listfilters'] = Array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
$supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters rules based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator value)');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['stats'] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
$supportedArguments['apitimeout'] = Array('niceName' => 'apiTimeout', 'shortHelp' => 'in case API takes too long time to anwer, increase this value (default=60)');



/***************************************
 *
 *         Supported Actions
 *
 **************************************/
$supportedActions = Array();
$commonActionFunctions = Array();

$commonActionFunctions['calculate-zones'] = function (CallContext $context, $fromOrTo)
{
    $rule = $context->object;

    if( $fromOrTo == 'from' )
    {
        $zoneContainer  = $rule->from;
        $addrContainer = $rule->source;
    }
    elseif( $fromOrTo == 'to' )
    {
        $zoneContainer  = $rule->to;
        $addrContainer = $rule->destination;
    }
    else
        derr('unsupported');

    $mode = $context->arguments['mode'];
    $system = $rule->owner->owner;

    /** @var VirtualRouter $virtualRouterToProcess */
    $virtualRouterToProcess = null;

    if( !isset($context->cachedIPmapping) )
        $context->cachedIPmapping = Array();

    $serial = spl_object_hash($rule->owner);
    $configIsOnLocalFirewall = false;

    if( !isset($context->cachedIPmapping[$serial]) )
    {
        if( $system->isDeviceGroup() || $system->isPanorama() )
        {
            $panconf = null;
            $panorama = $system;
            if( $system->isDeviceGroup() )
                $panorama = $system->owner;

            if( $context->arguments['template'] == $context->actionRef['args']['template']['default'] )
                derr('with Panorama configs, you need to specify a template name');

            if( $context->arguments['virtualRouter'] == $context->actionRef['args']['virtualRouter']['default'] )
                derr('with Panorama configs, you need to specify virtualRouter argument');

            $_tmp_explTemplateName = explode('@', $context->arguments['template']);
            if( count($_tmp_explTemplateName) > 1 )
            {
                if( $_tmp_explTemplateName[0] == 'api' )
                {
                    $configIsOnLocalFirewall = true;
                    $panoramaConnector = findConnector($system);
                    $connector = new PanAPIConnector($panoramaConnector->apihost, $panoramaConnector->apikey, 'panos-via-panorama', $_tmp_explTemplateName[1]);
                    $panconf = new PANConf();
                    $panconf->connector = $connector;
                    $panconf->load_from_domxml($connector->getCandidateConfig());
                }
            }


            /** @var Template $template */
            if( !$configIsOnLocalFirewall )
            {
                $template = $panorama->findTemplate($context->arguments['template']);
                if ($template === null)
                    derr("cannot find Template named '{$context->arguments['template']}'. Available template list:" . PH::list_to_string($panorama->templates));
            }

            if( $configIsOnLocalFirewall )
                $virtualRouterToProcess = $panconf->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);
            else
                $virtualRouterToProcess = $template->deviceConfiguration->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);

            if( $virtualRouterToProcess === null )
            {
                if( $configIsOnLocalFirewall )
                    $tmpVar = $panconf->network->virtualRouterStore->virtualRouters();
                else
                    $tmpVar = $template->deviceConfiguration->network->virtualRouterStore->virtualRouters();

                derr("cannot find VirtualRouter named '{$context->arguments['virtualRouter']}' in Template '{$context->arguments['template']}'. Available VR list: " . PH::list_to_string($tmpVar));
            }

            if( ( !$configIsOnLocalFirewall && count($template->deviceConfiguration->virtualSystems) == 1) || ($configIsOnLocalFirewall && count($panconf->virtualSystems) == 1))
            {
                if( $configIsOnLocalFirewall )
                    $system = $panconf->virtualSystems[0];
                    else
                $system = $template->deviceConfiguration->virtualSystems[0];
            }
            else
            {
                $vsysConcernedByVR = $virtualRouterToProcess->findConcernedVsys();
                if(count($vsysConcernedByVR) == 1)
                {
                    $system = array_pop($vsysConcernedByVR);
                }
                elseif( $context->arguments['vsys'] == '*autodetermine*')
                {
                    derr("cannot autodetermine resolution context from Template '{$context->arguments['template']}' VR '{$context->arguments['virtualRouter']}'' , multiple VSYS are available: ".PH::list_to_string($vsysConcernedByVR).". Please provide choose a VSYS.");
                }
                else
                {
                    if( $configIsOnLocalFirewall )
                        $vsys = $panconf->findVirtualSystem($context->arguments['vsys']);
                    else
                        $vsys = $template->deviceConfiguration->findVirtualSystem($context->arguments['vsys']);
                    if( $vsys === null )
                        derr("cannot find VSYS '{$context->arguments['vsys']}' in Template '{$context->arguments['template']}'");
                    $system = $vsys;
                }
            }

            //derr(DH::dom_to_xml($template->deviceConfiguration->xmlroot));
            //$tmpVar = $system->importedInterfaces->interfaces();
            //derr(count($tmpVar)." ".PH::list_to_string($tmpVar));
        }
        else if ($context->arguments['virtualRouter'] != '*autodetermine*')
        {
            $virtualRouterToProcess = $system->owner->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);
            if( $virtualRouterToProcess === null )
                derr("VirtualRouter named '{$context->arguments['virtualRouter']}' not found");
        }
        else
        {
            $vRouters = $system->owner->network->virtualRouterStore->virtualRouters();
            $foundRouters = Array();

            foreach ($vRouters as $router)
            {
                foreach ($router->attachedInterfaces->interfaces() as $if)
                {
                    if ($system->importedInterfaces->hasInterfaceNamed($if->name()))
                    {
                        $foundRouters[] = $router;
                        break;
                    }
                }
            }

            print $context->padding . " - VSYS/DG '{$system->name()}' has interfaces attached to " . count($foundRouters) . " virtual routers\n";
            if (count($foundRouters) > 1)
                derr("more than 1 suitable virtual routers found, please specify one fo the following: " . PH::list_to_string($foundRouters));
            if (count($foundRouters) == 0)
                derr("no suitable VirtualRouter found, please force one or check your configuration");

            $virtualRouterToProcess = $foundRouters[0];
        }
        $context->cachedIPmapping[$serial] = $virtualRouterToProcess->getIPtoZoneRouteMapping($system);
    }


    $ipMapping = &$context->cachedIPmapping[$serial];

    if( $rule->isSecurityRule() )
        $resolvedZones = & $addrContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4'], $rule->sourceIsNegated());
    else
        $resolvedZones = & $addrContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4']);

    if( count($resolvedZones) == 0 )
    {
        print $context->padding." - WARNING : no zone resolved (FQDN? IPv6?)\n";
        return;
    }


    $plus = Array();
    foreach( $zoneContainer->zones() as $zone )
        $plus[$zone->name()] = $zone->name();

    $minus = Array();
    $common = Array();

    foreach( $resolvedZones as $zoneName => $zone )
    {
        if( isset($plus[$zoneName]) )
        {
            unset($plus[$zoneName]);
            $common[] = $zoneName;
            continue;
        }
        $minus[] = $zoneName;
    }

    if( count($common) > 0 )
        print $context->padding." - untouched zones: ".PH::list_to_string($common)."\n";
    if( count($minus) > 0 )
        print $context->padding." - missing zones: ".PH::list_to_string($minus)."\n";
    if( count($plus) > 0 )
        print $context->padding." - uneeded zones: ".PH::list_to_string($plus)."\n";

    if( $mode == 'replace' )
    {
        print $context->padding." - REPLACE MODE, syncing with (".count($resolvedZones).") resolved zones.";
        if( $addrContainer->isAny() )
            print " *** IGNORED because value is 'ANY' ***\n";
        elseif(count($resolvedZones) == 0)
            print " *** IGNORED because no zone was resolved ***\n";
        else
        {
            print "\n";
            $zoneContainer->setAny();
            foreach( $resolvedZones as $zone )
                $zoneContainer->addZone($zoneContainer->parentCentralStore->findOrCreate($zone));
            if( $context->isAPI )
                $zoneContainer->API_sync();
        }
    }
    elseif( $mode == 'append' )
    {
        print $context->padding." - APPEND MODE: adding missing (".count($minus).") zones only.";
        if( $addrContainer->isAny() )
            print " *** IGNORED because value is 'ANY' ***\n";
        elseif(count($minus) == 0)
            print " *** IGNORED because no missing zones were found ***\n";
        else
        {
            print "\n";
            foreach( $minus as $zone )
                $zoneContainer->addZone($zoneContainer->parentCentralStore->findOrCreate($zone));
            if( $context->isAPI )
                $zoneContainer->API_sync();
        }
    }
};



// <editor-fold desc="Supported Actions Array" defaultstate="collapsed" >

  //                                              //
 //                Zone Based Actions            //
//                                              //
$supportedActions['from-add'] = Array(
    'name' => 'from-Add',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->find($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->from->API_addZone($objectFind);
        else
            $rule->from->addZone($objectFind);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['from-add-force'] = Array(
    'name' => 'from-Add-Force',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->findOrCreate($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->from->API_addZone($objectFind);
        else
            $rule->from->addZone($objectFind);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['from-remove'] = Array(
    'name' => 'from-Remove',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->find($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->from->API_removeZone($objectFind);
        else
            $rule->from->removeZone($objectFind);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['from-remove-force-any'] = Array(
    'name' => 'from-Remove-Force-Any',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->find($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->from->API_removeZone($objectFind, true, true);
        else
            $rule->from->removeZone($objectFind, true, true);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['from-set-any'] = Array(
    'name' => 'from-Set-Any',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if ($context->isAPI)
            $rule->from->API_setAny();
        else
            $rule->from->setAny();
    },
);

$supportedActions['to-add'] = Array(
    'name' => 'to-Add',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->find($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->to->API_addZone($objectFind);
        else
            $rule->to->addZone($objectFind);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['to-add-force'] = Array(
    'name' => 'to-Add-Force',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->findOrCreate($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->to->API_addZone($objectFind);
        else
            $rule->to->addZone($objectFind);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['to-remove'] = Array(
    'name' => 'to-Remove',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->find($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->to->API_removeZone($objectFind);
        else
            $rule->to->removeZone($objectFind);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['to-remove-force-any'] = Array(
    'name' => 'to-Remove-Force-Any',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->from->parentCentralStore->find($context->arguments['zoneName']);
        if( $objectFind === null )
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $rule->to->API_removeZone($objectFind, true, true);
        else
            $rule->to->removeZone($objectFind, true, true);
    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['to-set-any'] = Array(
    'name' => 'to-Set-Any',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( $context->isAPI )
            $rule->to->API_setAny();
        else
            $rule->to->setAny();
    },
);

$supportedActions['from-calculate-zones'] = Array(
    'name' => 'from-calculate-zones',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        global $commonActionFunctions;

        $commonActionFunctions['calculate-zones']($context, 'from');
    },
    'args' => Array(    'mode' => Array( 'type' => 'string', 'default' => 'append', 'choices' => Array('replace', 'append', 'show') ),
                        'virtualRouter' => Array('type' => 'string', 'default' => '*autodetermine*'),
                        'template' => Array('type' => 'string', 'default' => '*notPanorama*'),
                        'vsys' => Array('type' => 'string', 'default' => '*autodetermine*'),
    ),
);
$supportedActions['to-calculate-zones'] = Array(
    'name' => 'to-calculate-zones',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        global $commonActionFunctions;

        $commonActionFunctions['calculate-zones']($context, 'to');
    },
    'args' => Array(    'mode' => Array( 'type' => 'string', 'default' => 'append', 'choices' => Array('replace', 'append', 'show') ),
        'virtualRouter' => Array('type' => 'string', 'default' => '*autodetermine*'),
        'template' => Array('type' => 'string', 'default' => '*notPanorama*'),
        'vsys' => Array('type' => 'string', 'default' => '*autodetermine*'),
    ),
);


  //                                                    //
 //                Source/Dest Based Actions           //
//                                                    //
$supportedActions['src-add'] = Array(
    'name' => 'src-Add',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->source->parentCentralStore->find($context->arguments['objName']);
        if( $objectFind === null )
            derr("address-type object named '{$context->arguments['objName']}' not found");

        if( $context->isAPI )
            $rule->source->API_add($objectFind);
        else
            $rule->source->addObject($objectFind);
    },
    'args' => Array( 'objName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['src-remove'] = Array(
    'name' => 'src-Remove',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->source->parentCentralStore->find($context->arguments['objName']);
        if( $objectFind === null )
            derr("address-type object named '{$context->arguments['objName']}' not found");

        if( $context->isAPI )
            $rule->source->API_remove($objectFind);
        else
            $rule->source->remove($objectFind);
    },
    'args' => Array( 'objName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['src-remove-force-any'] = Array(
    'name' => 'src-Remove-Force-Any',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->source->parentCentralStore->find($context->arguments['objName']);
        if( $objectFind === null )
            derr("address-type object named '{$context->arguments['objName']}' not found");

        if( $context->isAPI )
            $rule->source->API_remove($objectFind, true);
        else
            $rule->source->remove($objectFind, true, true);
    },
    'args' => Array( 'objName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['dst-add'] = Array(
    'name' => 'dst-Add',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->source->parentCentralStore->find($context->arguments['objName']);
        if( $objectFind === null )
            derr("address-type object named '{$context->arguments['objName']}' not found");

        if( $context->isAPI )
            $rule->destination->API_add($objectFind);
        else
            $rule->destination->addObject($objectFind);
    },
    'args' => Array( 'objName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['dst-remove'] = Array(
    'name' => 'dst-Remove',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->source->parentCentralStore->find($context->arguments['objName']);
        if( $objectFind === null )
            derr("address-type object named '{$context->arguments['objName']}' not found");

        if( $context->isAPI )
            $rule->destination->API_remove($objectFind);
        else
            $rule->destination->remove($objectFind);
    },
    'args' => Array( 'objName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['dst-remove-force-any'] = Array(
    'name' => 'dst-Remove-Force-Any',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->source->parentCentralStore->find($context->arguments['objName']);
        if( $objectFind === null )
            derr("address-type object named '{$context->arguments['objName']}' not found");

        if( $context->isAPI )
            $rule->destination->API_remove($objectFind, true);
        else
            $rule->destination->remove($objectFind, true, true);
    },
    'args' => Array( 'objName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['src-set-any'] = Array(
    'name' => 'src-set-Any',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->source->API_setAny();
        else
            $rule->source->setAny();
    },
);
$supportedActions['dst-set-any'] = Array(
    'name' => 'dst-set-Any',
    'section' => 'address',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->destination->API_setAny();
        else
            $rule->destination->setAny();
    },
);


  //                                                 //
 //              Tag property Based Actions         //
//                                                 //
$supportedActions['tag-add'] = Array(
    'name' => 'tag-Add',
    'section' => 'tag',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $rule->tags->API_addTag($objectFind);
        else
            $rule->tags->addTag($objectFind);
    },
    'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['tag-add-force'] = Array(
    'name' => 'tag-Add-Force',
    'section' => 'tag',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
        {
            $objectFind = $rule->tags->parentCentralStore->find($context->arguments['tagName']);
            if( $objectFind === null)
                $objectFind = $rule->tags->parentCentralStore->API_createTag($context->arguments['tagName']);
        }
        else
            $objectFind = $rule->tags->parentCentralStore->find($context->arguments['tagName']);

        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $rule->tags->API_addTag($objectFind);
        else
            $rule->tags->addTag($objectFind);
    },
    'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['tag-remove'] = Array(
    'name' => 'tag-Remove',
    'section' => 'tag',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $rule->tags->API_removeTag($objectFind);
        else
            $rule->tags->removeTag($objectFind);
    },
    'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['tag-remove-regex'] = Array(
    'name' => 'tag-Remove-Regex',
    'section' => 'tag',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $pattern = '/'.$context->arguments['regex'].'/';
        foreach($rule->tags->tags() as $tag )
        {
            $result = preg_match($pattern, $tag->name());
            if( $result === false )
                derr("'$pattern' is not a valid regex");
            if( $result == 1 )
            {
                print $context->padding."  - removed tag {$tag->name()}\n";
                if( $context->isAPI )
                    $rule->tags->API_removeTag($tag);
                else
                    $rule->tags->removeTag($tag);
            }
        }
    },
    'args' => Array( 'regex' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);


  //                                                   //
 //                Services Based Actions             //
//                                                   //
$supportedActions['service-set-appdefault'] = Array(
    'name' => 'service-Set-AppDefault',
    'section' => 'service',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( $context->isAPI )
            $rule->services->API_setApplicationDefault();
        else
            $rule->services->setApplicationDefault();
    },
);
$supportedActions['service-set-any'] = Array(
    'name' => 'service-Set-Any',
    'section' => 'service',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( $context->isAPI )
            $rule->services->API_setAny();
        else
            $rule->services->setAny();
    },
);
$supportedActions['service-add'] = Array(
    'name' => 'service-Add',
    'section' => 'service',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->services->parentCentralStore->find($context->arguments['svcName']);
        if( $objectFind === null )
            derr("service named '{$context->arguments['svcName']}' not found");

        if( $context->isAPI )
            $rule->services->API_add($objectFind);
        else
            $rule->services->addObject($objectFind);
    },
    'args' => Array( 'svcName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['service-remove'] = Array(
    'name' => 'service-Remove',
    'section' => 'service',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->services->parentCentralStore->find($context->arguments['svcName']);
        if( $objectFind === null )
            derr("service named '{$context->arguments['svcName']}' not found");

        if( $context->isAPI )
            $rule->services->API_remove($objectFind);
        else
            $rule->services->remove($objectFind);
    },
    'args' => Array( 'svcName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['service-remove-force-any'] = Array(
    'name' => 'service-Remove-Force-Any',
    'section' => 'service',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->services->parentCentralStore->find($context->arguments['svcName']);
        if( $objectFind === null )
            derr("service named '{$context->arguments['svcName']}' not found");

        if( $context->isAPI )
            $rule->services->API_remove($objectFind, true, true);
        else
            $rule->services->remove($objectFind, true, true);
    },
    'args' => Array( 'svcName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);


  //                                                   //
 //                App Based Actions                  //
//                                                   //
$supportedActions['app-set-any'] = Array(
    'name' => 'app-Set-Any',
    'section' => 'app',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->apps->API_setAny();
        else
            $rule->apps->setAny();
    },
);
$supportedActions['app-add'] = Array(
    'name' => 'app-Add',
    'section' => 'app',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->apps->parentCentralStore->find($context->arguments['appName']);
        if( $objectFind === null )
            derr("application named '{$context->arguments['appName']}' not found");

        if( $context->isAPI )
            $rule->apps->API_addApp($objectFind);
        else
            $rule->apps->addApp($objectFind);
    },
    'args' => Array( 'appName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['app-remove'] = Array(
    'name' => 'app-Remove',
    'section' => 'app',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->apps->parentCentralStore->find($context->arguments['appName']);
        if( $objectFind === null )
            derr("application named '{$context->arguments['appName']}' not found");

        if( $context->isAPI )
            $rule->apps->API_removeApp($objectFind);
        else
            $rule->apps->removeApp($objectFind);
    },
    'args' => Array( 'appName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
$supportedActions['app-remove-force-any'] = Array(
    'name' => 'app-Remove-Force-Any',
    'section' => 'app',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $objectFind = $rule->apps->parentCentralStore->find($context->arguments['appName']);
        if( $objectFind === null )
            derr("application named '{$context->arguments['appName']}' not found");

        if( $context->isAPI )
            $rule->apps->API_removeApp($objectFind, true, true);
        else
            $rule->apps->removeApp($objectFind, true, true);
    },
    'args' => Array( 'appName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);



  //                                                 //
 //               Log based Actions                 //
//                                                 //
$supportedActions['logstart-enable'] = Array(
    'name' => 'logStart-enable',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setLogStart(true);
        else
            $rule->setLogStart(true);
    },
);
$supportedActions['logstart-disable'] = Array(
    'name' => 'logStart-disable',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setLogStart(false);
        else
            $rule->setLogStart(false);
    },
);
$supportedActions['logend-enable'] = Array(
    'name' => 'logEnd-enable',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setLogEnd(true);
        else
            $rule->setLogEnd(true);
    }
);

$supportedActions['logend-disable'] = Array(
    'name' => 'logEnd-disable',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setLogEnd(false);
        else
            $rule->setLogEnd(false);
    }
);
$supportedActions['logsetting-set'] = Array(
    'name' => 'logSetting-set',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setLogSetting($context->arguments['profName']);
        else
            $rule->setLogSetting($context->arguments['profName']);
    },
    'args' => Array( 'profName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) )
);



//                                                   //
//                Security profile Based Actions       //
//                                                   //
$supportedActions['securityprofile-group-set'] = Array(
    'name' => 'securityProfile-Group-Set',
    'MainFunction' =>  function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setSecurityProfileGroup($context->arguments['profName']);
        else
            $rule->setSecurityProfileGroup($context->arguments['profName']);
    },
    'args' => Array( 'profName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) )
);

$supportedActions['description-append'] = Array(
    'name' => 'description-Append',
    'MainFunction' =>  function(RuleCallContext $context)
    {
        $rule = $context->object;
        $description = ' '.$rule->description();

        $textToAppend = $context->arguments['text'];

        if( strlen($description) + strlen($textToAppend) > 253 )
        {
            print $context->padding." - SKIPPED : description is too long\n";
            return;
        }

        if( $context->isAPI )
            $rule->API_setDescription($description.$textToAppend);
        else
            $rule->setSecurityProfileGroup($description.$textToAppend);
    },
    'args' => Array( 'text' => Array( 'type' => 'string', 'default' => '*nodefault*' ) )
);


//                                                   //
//                Other property Based Actions       //
//                                                   //
$supportedActions['enabled-set'] = Array(
    'name' => 'enable-Set',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setEnabled($context->arguments['trueOrFalse']);
        else
            $rule->setEnabled($context->arguments['trueOrFalse']);
    },
    'args' => Array(    'trueOrFalse' => Array( 'type' => 'bool', 'default' => 'yes'  ) )
);
$supportedActions['enabled-set-fastapi'] = Array(
    'name' => 'enabled-Set-FastAPI',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( !$context->isAPI )
            derr('you cannot call this action without API mode');

        if( $rule->setEnabled($context->arguments['trueOrFalse']) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<disabled>' . boolYesNo(!$context->arguments['trueOrFalse']) . '</disabled>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $setString = $context->generateRuleMergedApuChangeString(true);
        if( $setString !== null )
        {
            print $context->padding . ' - sending API call for SHARED... ';
            $context->connector->sendSetRequest('/config/shared', $setString);
            print "OK!\n";
        }
        $setString = $context->generateRuleMergedApuChangeString(false);
        if( $setString !== null )
        {
            print $context->padding . ' - sending API call for Device-Groups... ';
            $context->connector->sendSetRequest("/config/devices/entry[@name='localhost.localdomain']", $setString);
            print "OK!\n";
        }
    },
    'args' => Array(    'trueOrFalse' => Array( 'type' => 'bool', 'default' => 'yes'  ) )
);
$supportedActions['disabled-set'] = Array(
    'name' => 'disable-Set',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->API_setDisabled($context->arguments['trueOrFalse']);
        else
            $rule->setDisabled($context->arguments['trueOrFalse']);
    },
    'args' => Array(    'trueOrFalse' => Array( 'type' => 'bool', 'default' => 'yes'  ) )
);
$supportedActions['disabled-set-fastapi'] = Array(
    'name' => 'disable-Set-FastAPI',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( !$context->isAPI )
            derr('you cannot call this action without API mode');

        if( $rule->setDisabled($context->arguments['trueOrFalse']) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<disabled>' . boolYesNo($context->arguments['trueOrFalse']) . '</disabled>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $setString = $context->generateRuleMergedApuChangeString(true);
        if( $setString !== null )
        {
            print $context->padding . ' - sending API call for SHARED... ';
            $context->connector->sendSetRequest('/config/shared', $setString);
            print "OK!\n";
        }
        $setString = $context->generateRuleMergedApuChangeString(false);
        if( $setString !== null )
        {
            print $context->padding . ' - sending API call for Device-Groups... ';
            $context->connector->sendSetRequest("/config/devices/entry[@name='localhost.localdomain']", $setString);
            print "OK!\n";
        }
    },
    'args' => Array(    'trueOrFalse' => Array( 'type' => 'bool', 'default' => 'yes'  ) )
);
$supportedActions['delete'] = Array(
    'name' => 'delete',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        if( $context->isAPI )
            $rule->owner->API_remove($rule);
        else
            $rule->owner->remove($rule);
    }
);
$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function(RuleCallContext $context) { $context->object->display(7); }
);
$supportedActions['invertpreandpost'] = Array(
    'name' => 'invertPreAndPost',
    'MainFunction' => function(RuleCallContext $context)
                    {
                        if( !$context->isAPI )
                        {
                            if( $context->object->isPreRule() )
                                $context->object->owner->moveRuleToPostRulebase($context->object);
                            else if( $context->object->isPostRule() )
                                $context->object->owner->moveRuleToPreRulebase($context->object);
                            else
                                derr('unsupported');
                        }
                        else
                        {
                            if( $context->object->isPreRule() )
                                $context->object->owner->API_moveRuleToPostRulebase($context->object);
                            else if( $context->object->isPostRule() )
                                $context->object->owner->API_moveRuleToPreRulebase($context->object);
                            else
                                derr('unsupported');
                        }
                    }
);


$supportedActions['copy'] = Array(
    'name' => 'copy',
    'MainFunction' => function(RuleCallContext $context)
                {
                    $rule = $context->object;
                    $args = &$context->arguments;
                    $location = $args['location'];
                    $pan = PH::findRootObjectOrDie($rule);;

                    if( $args['preORpost'] == "post" )
                        $preORpost = true;
                    else
                        $preORpost = false;


                    /** @var RuleStore $ruleStore */
                    $ruleStore = null;
                    $variableName = $rule->storeVariableName();

                    if( strtolower($location) == 'shared' )
                    {
                        if( $pan->isPanOS() )
                            derr("Rules cannot be copied to SHARED location on a firewall, only in Panorama");

                        $ruleStore = $pan->$variableName;
                    }
                    else
                    {
                        $sub = $pan->findSubSystemByName($location);
                        if( $sub === null )
                            derr("cannot find vsys or device group named '{$location}'");
                        $ruleStore = $sub->$variableName;
                    }
                    if( $context->isAPI )
                        $ruleStore->API_cloneRule($rule, null, $preORpost);
                    else
                        $ruleStore->cloneRule($rule, null, $preORpost);
                },
    'args' => Array(    'location' => Array( 'type' => 'string', 'default' => '*nodefault*'  ),
                            'preORpost' => Array( 'type' => 'string', 'default' => 'pre', 'choices' => Array('pre','post') ) )
);

$supportedActions['exporttoexcel'] = Array(
    'name' => 'exportToExcel',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $context->ruleList[] = $rule;
    },
    'GlobalInitFunction' => function(RuleCallContext $context)
    {
        $context->ruleList = Array();
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;
        $args = &$context->arguments;
        $filename = $args['filename'];

        $lines = '';
        $encloseFunction  = function($value, $nowrap = true)
        {
            if( is_string($value) )
                $output = htmlspecialchars($value);
            elseif( is_array($value) )
            {
                $output = '';
                $first = true;
                foreach( $value as $subValue )
                {
                    if( !$first )
                    {
                        $output .= '<br />';
                    }
                    else
                        $first= false;

                    if( is_string($subValue) )
                        $output .= htmlspecialchars($subValue);
                    else
                        $output .= htmlspecialchars($subValue->name());
                }
            }
            else
                derr('unsupported');

            if( $nowrap )
                return '<td style="white-space: nowrap">'.$output.'</td>';

            return '<td>'.$output.'</td>';
        };

        $count = 0;
        if( isset($context->ruleList) )
        {
            foreach ($context->ruleList as $rule)
            {
                $count++;

                /** @var SecurityRule|NatRule $rule */
                if ($count % 2 == 1)
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                if ($rule->owner->owner->isPanorama() || $rule->owner->owner->isPanOS())
                    $lines .= $encloseFunction('shared');
                else
                    $lines .= $encloseFunction($rule->owner->owner->name());


                if ($rule->isSecurityRule())
                    $lines .= $encloseFunction('security');
                elseif ($rule->isNatRule())
                    $lines .= $encloseFunction('nat');
                else $lines .= $encloseFunction('unknown');

                $lines .= $encloseFunction($rule->name());

                if ($rule->from->isAny())
                    $lines .= $encloseFunction('any');
                else
                {
                    $tmpArray = $rule->from->getAll();
                    $lines .= $encloseFunction($rule->from->getAll());
                }

                if ($rule->source->isAny())
                    $lines .= $encloseFunction('any');
                else
                {
                    $lines .= $encloseFunction($rule->source->getAll());
                }

                if ($rule->to->isAny())
                    $lines .= $encloseFunction('any');
                else
                {
                    $lines .= $encloseFunction($rule->to->getAll());
                }

                if ($rule->destination->isAny())
                    $lines .= $encloseFunction('any');
                else
                {
                    $lines .= $encloseFunction($rule->destination->getAll());
                }

                if ($rule->isSecurityRule())
                {
                    if ($rule->services->isAny())
                        $lines .= $encloseFunction('any');
                    elseif ($rule->services->isApplicationDefault())
                        $lines .= $encloseFunction('application-default');
                    else
                    {
                        $lines .= $encloseFunction($rule->services->getAll());
                    }
                } elseif ($rule->isNatRule())
                {
                    if ($rule->service !== null)
                        $lines .= $encloseFunction($rule->service->name());
                    else
                        $lines .= $encloseFunction('any');
                } else
                    $lines .= $encloseFunction('');

                if ($rule->isSecurityRule())
                {
                    if ($rule->apps->isAny())
                        $lines .= $encloseFunction('any');
                    else
                    {
                        $lines .= $encloseFunction($rule->apps->getAll());
                    }
                } else
                    $lines .= $encloseFunction('');

                if ($rule->isSecurityRule())
                {
                    $lines .= $encloseFunction($rule->action());
                    $lines .= $encloseFunction(boolYesNo($rule->logStart()));
                    $lines .= $encloseFunction(boolYesNo($rule->logEnd()));
                } else
                {
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction('');
                }

                $lines .= $encloseFunction(boolYesNo($rule->isDisabled()));
                $lines .= $encloseFunction(htmlspecialchars($rule->description()), false);

                if ($rule->isNatRule())
                {
                    $natType = $rule->natType();
                    $lines .= $encloseFunction($natType);
                    if ($natType == 'none')
                        $lines .= $encloseFunction('');
                    elseif($natType == 'static-ip' || $natType == 'dynamic-ip' || $natType == 'dynamic-ip-and-port')
                    {
                        $lines .= $encloseFunction($rule->snathosts->all());
                    } else
                        $lines .= $encloseFunction('unsupported');

                    if( $rule->dnathost !== null )
                    {
                        $lines .= $encloseFunction($rule->dnathost->name());
                    }
                    else
                        $lines .= $encloseFunction('');

                    if( $rule->dnatports !== null )
                    {
                        $lines .= $encloseFunction($rule->dnatports->name());
                    }
                    else
                        $lines .= $encloseFunction('');

                } else
                {
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction('');
                }


                $lines .= "</tr>\n";

            }
        }

        $content = file_get_contents(dirname(__FILE__).'/common/html-export-template.html');
        $content = str_replace('%TableHeaders%',
            '<th>location</th><th>type</th><th>name</th><th>from</th><th>src</th><th>to</th><th>dst</th><th>service</th><th>application</th>'.
            '<th>action</th><th>log start</th><th>log end</th><th>disabled</th><th>description</th>'.
            '<th>SNAT type</th><th>SNAT hosts</th><th>DNAT host</th><th>DNAT port</th>',
            $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent =  file_get_contents(dirname(__FILE__).'/common/jquery-1.11.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__).'/common/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    },
    'args' => Array(    'filename' => Array( 'type' => 'string', 'default' => '*nodefault*'  ) )
);

$supportedActions['cloneforappoverride'] = Array(
    'name' => 'cloneForAppOverride',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( $rule->actionIsNegative() )
        {
            print $context->padding . " - IGNORED because Action is DENY\n";
            return;
        }

        if( !$rule->apps->isAny() )
        {
            print $context->padding . " - IGNORED because Application is NOT EQUAL ANY\n";
            return;
        }

        $ports = '';

        if( ($rule->services->isAny() || $rule->services->isApplicationDefault()) && !$context->arguments['restrictToListOfServices'] == '*sameAsInRule*' )
        {
            $ports = '1-65535';
            $portMapping = ServiceDstPortMapping::mappingFromText($ports, true);
            $udpPortMapping = ServiceDstPortMapping::mappingFromText($ports, false);

            $portMapping->mergeWithMapping($udpPortMapping);
        }
        else
        {
            $portMapping = new ServiceDstPortMapping();

            if( $context->arguments['restrictToListOfServices'] == '*sameAsInRule*' )
            {
                $services = $rule->services->members();
            }
            else
            {
                $listOfServicesQueryName = $context->arguments['restrictToListOfServices'];
                if( !isset($context->nestedQueries[$listOfServicesQueryName]) )
                {
                    derr("cannot find query filter called '$listOfServicesQueryName'");
                }

                $rQuery = new RQuery('service');
                $errorMessage = '';
                if( !$rQuery->parseFromString($context->nestedQueries[$listOfServicesQueryName], $errorMessage) )
                    derr("error while parsing query: {$context->nestedQueries[$listOfServicesQueryName]}");

                $services = Array();

                foreach( $rule->services->membersExpanded() as $member )
                {
                    if( $rQuery->matchSingleObject($member) )
                    {
                        $services[] = $member;
                    }
                }
            }
            if( count($services) == 0)
            {
                print $context->padding." - IGNORED because NO MATCHING SERVICE FOUND\n";
                return;
            }
            $portMapping->mergeWithArrayOfServiceObjects($services);
        }

        $application = $rule->apps->parentCentralStore->findOrCreate($context->arguments['applicationName']);

        print $context->padding." - Port mapping to import in AppOverride: ".$portMapping->mappingToText()."\n";
        if( count($portMapping->tcpPortMap) > 0)
        {
            $newName = $rule->owner->owner->appOverrideRules->findAvailableName($rule->name(), '');
            $newRule = $rule->owner->owner->appOverrideRules->newAppOverrideRule($newName, $rule->isPostRule());
            if( $rule->sourceIsNegated() )
                $newRule->setSourceIsNegated(true);
            if( $rule->destinationIsNegated() )
                $newRule->setDestinationIsNegated(true);

            $newRule->from->copy($rule->from);
            $newRule->to->copy($rule->to);
            $newRule->source->copy($rule->source);
            $newRule->destination->copy($rule->destination);
            $newRule->setTcp();
            $newRule->setPorts($portMapping->tcpMappingToText());
            $newRule->setApplication($application);

            if( $context->isAPI )
                $newRule->API_sync();
            print $context->padding." - created TCP appOverride rule '{$newRule->name()}'\n";
        }
        if( count($portMapping->udpPortMap) > 0)
        {
            $newName = $rule->owner->owner->appOverrideRules->findAvailableName($rule->name(), '');
            $newRule = $rule->owner->owner->appOverrideRules->newAppOverrideRule($newName, $rule->isPreRule());
            if( $rule->sourceIsNegated() )
                $newRule->setSourceIsNegated(true);
            if( $rule->destinationIsNegated() )
                $newRule->setDestinationIsNegated(true);

            $newRule->from->copy($rule->from);
            $newRule->to->copy($rule->to);
            $newRule->source->copy($rule->source);
            $newRule->destination->copy($rule->destination);
            $newRule->setUdp();
            $newRule->setPorts($portMapping->udpMappingToText());
            $newRule->setApplication($application);

            if( $context->isAPI )
                $newRule->API_sync();
            print $context->padding." - created TCP appOverride rule '{$newRule->name()}'\n";
        }


    },
    'args' => Array(    'applicationName' => Array( 'type' => 'string', 'default' => '*nodefault*'  ),
                        'restrictToListOfServices' => Array( 'type' => 'string', 'default' => '*sameAsInRule*'  ), )
);
// </editor-fold>
//TODO add action==move
/************************************ */


PH::processCliArgs();

$nestedQueries = Array();

foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        if( strpos($index,'subquery') === 0 )
        {
            $nestedQueries[$index] = &$arg;
            continue;
        }
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}

if( isset(PH::$args['listactions']) )
{
    ksort($supportedActions);

    print "Listing of supported actions:\n\n";

    print str_pad('', 100, '-')."\n";
    print str_pad('Action name', 28, ' ', STR_PAD_BOTH)."|".str_pad("Argument:Type",24, ' ', STR_PAD_BOTH)." |".
            str_pad("Def. Values",12, ' ', STR_PAD_BOTH)."|   Choices\n";
    print str_pad('', 100, '-')."\n";

    foreach($supportedActions as &$action )
    {

        $output = "* ".$action['name'];

        $output = str_pad($output, 28).'|';

        if( isset($action['args']) )
        {
            $first = true;
            $count=1;
            foreach($action['args'] as $argName => &$arg)
            {
                if( !$first )
                    $output .= "\n".str_pad('',28).'|';

                $output .= " ".str_pad("#$count $argName:{$arg['type']}", 24)."| ".str_pad("{$arg['default']}",12)."| ";
                if( isset($arg['choices']) )
                {
                    $output .= PH::list_to_string($arg['choices']);
                }

                $count++;
                $first = false;
            }
        }


        print $output."\n";

        print str_pad('', 100, '=')."\n";

        //print "\n";
    }

    exit(0);
}

if( isset(PH::$args['listfilters']) )
{
    ksort(RQuery::$defaultFilters['rule']);

    print "Listing of supported filters:\n\n";

    foreach(RQuery::$defaultFilters['rule'] as $index => &$filter )
    {
        print "* ".$index."\n";
        ksort( $filter['operators'] );

        foreach( $filter['operators'] as $oindex => &$operator)
        {
            //if( $operator['arg'] )
            $output = "    - $oindex";

            print $output."\n";
        }
        print "\n";
    }

    exit(0);
}




if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');


if( !isset(PH::$args['apitimeout']) )
{
    $apiTimeoutValue = 60;
}
else
    $apiTimeoutValue = PH::$args['apitimeout'];


if( ! isset(PH::$args['actions']) )
    display_error_usage_exit('"actions" is missing from arguments');
$doActions = PH::$args['actions'];
if( !is_string($doActions) || strlen($doActions) < 1 )
    display_error_usage_exit('"actions" argument is not a valid string');


if( isset(PH::$args['dryrun'])  )
{
    $dryRun = PH::$args['dryrun'];
    if( $dryRun === 'yes' ) $dryRun = true;
    if( $dryRun !== true || $dryRun !== false )
        display_error_usage_exit('"dryrun" argument has an invalid value');
}

if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}


//
// Rule filter provided in CLI ?
//
if( isset(PH::$args['filter'])  )
{
    $rulesFilter = PH::$args['filter'];
    if( !is_string($rulesFilter) || strlen($rulesFilter) < 1 )
        display_error_usage_exit('"filter" argument is not a valid string');
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
    print " - Downloading config from API... ";
    $xmlDoc = $configInput['connector']->getCandidateConfig($apiTimeoutValue);
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
    if( $configType == 'panos' )
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

//
// Determine rule types
//
$supportedRuleTypes = Array('all', 'any', 'security', 'nat', 'decryption', 'appoverride');
if( !isset(PH::$args['ruletype'])  )
{
    print " - No 'ruleType' specified, using 'security' by default\n";
    $ruleTypes = Array('security');
}
else
{
    $ruleTypes = explode(',', PH::$args['ruletype']);
    foreach( $ruleTypes as &$rType)
    {
        $rType = strtolower($rType);
        if( array_search($rType, $supportedRuleTypes) === false )
        {
            display_error_usage_exit("'ruleType' has unsupported value: '".$rType."'. Supported values are: ".PH::list_to_string($supportedRuleTypes));
        }
        if( $rType == 'all' )
            $rType = 'any';
    }

    $ruleTypes = array_unique($ruleTypes);
}



//
// Extracting actions
//
$explodedActions = explode('/', $doActions);
/** @var RuleCallContext[] $doActions */
$doActions = Array();
foreach( $explodedActions as &$exAction )
{
    $explodedAction = explode(':', $exAction);
    if( count($explodedAction) > 2 )
        display_error_usage_exit('"actions" argument has illegal syntax: '.PH::$args['actions']);

    $actionName = strtolower($explodedAction[0]);

    if( !isset($supportedActions[$actionName]) )
    {
        display_error_usage_exit('unsupported Action: "'.$actionName.'"');
    }

    if( count($explodedAction) == 1 )
        $explodedAction[1] = '';

    $context = new RuleCallContext($supportedActions[$actionName], $explodedAction[1], $nestedQueries);
    $context->baseObject = $pan;

    if( $configInput['type'] == 'api' )
    {
        $context->isAPI = true;
        $context->connector = $pan->connector;
    }

    $doActions[] = $context;
}
//
// ---------



//
// create a RQuery if a filter was provided
//
/**
 * @var RQuery $objectFilterRQuery
 */
$objectFilterRQuery = null;
if( $rulesFilter !== null )
{
    $objectFilterRQuery = new RQuery('rule');
    $res = $objectFilterRQuery->parseFromString($rulesFilter, $errorMessage);
    if( $res === false )
    {
        fwrite(STDERR, "\n\n**ERROR** Rule filter parser: " . $errorMessage . "\n\n");
        exit(1);
    }

    print " - Rule filter after sanitization: ";
    $objectFilterRQuery->display();
    print "\n";
}
// --------------------


//
// load the config
//
print " - Loading configuration through PAN-Configurator library... ";
$loadStartMem = memory_get_usage(true);
$loadStartTime = microtime(true);
$pan->load_from_domxml($xmlDoc);
$loadEndTime = microtime(true);
$loadEndMem = memory_get_usage(true);
$loadElapsedTime = number_format( ($loadEndTime - $loadStartTime), 2, '.', '');
$loadUsedMem = convert($loadEndMem - $loadStartMem);
print "OK! ($loadElapsedTime seconds, $loadUsedMem memory)\n";
// --------------------


//
// Location Filter Processing
//

// <editor-fold desc="Location Filter Processing" defaultstate="collapsed" >

/**@var RuleStore[] $ruleStoresToProcess */
$rulesLocation = explode(',', $rulesLocation);

foreach( $rulesLocation as &$location )
{
    if( strtolower($location) == 'shared' )
        $location = 'shared';
    else if( strtolower($location) == 'any' )
        $location = 'any';
    else if( strtolower($location) == 'all' )
        $location = 'any';
}
$rulesLocation = array_unique($rulesLocation);
$rulesToProcess = Array();

foreach( $rulesLocation as $location )
{
    $locationFound = false;

    if( $configType == 'panos')
    {
        foreach ($pan->getVirtualSystems() as $sub)
        {
            if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()]) ))
            {
                if( array_search('any', $ruleTypes) !== false || array_search('security', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->securityRules, 'rules' => $sub->securityRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('nat', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->natRules, 'rules' => $sub->natRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('decryption', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->decryptionRules, 'rules' => $sub->decryptionRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('appoverride', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->appOverrideRules, 'rules' => $sub->appOverrideRules->rules());
                }
                $locationFound = true;
            }
        }
    }
    else
    {
        if( $location == 'shared' || $location == 'any'  )
        {
            if( array_search('any', $ruleTypes) !== false || array_search('security', $ruleTypes) !== false )
            {
                $rulesToProcess[] = Array('store' => $pan->securityRules, 'rules' => $pan->securityRules->rules());
            }
            if( array_search('any', $ruleTypes) !== false || array_search('nat', $ruleTypes) !== false )
            {
                $rulesToProcess[] = Array('store' => $pan->natRules, 'rules' => $pan->natRules->rules());
            }
            if( array_search('any', $ruleTypes) !== false || array_search('decryption', $ruleTypes) !== false )
            {
                $rulesToProcess[] = Array('store' => $pan->decryptionRules, 'rules' => $pan->decryptionRules->rules());
            }
            if( array_search('any', $ruleTypes) !== false || array_search('appoverride', $ruleTypes) !== false )
            {
                $rulesToProcess[] = Array('store' => $pan->appOverrideRules, 'rules' => $pan->appOverrideRules->rules());
            }
            $locationFound = true;
        }

        foreach( $pan->getDeviceGroups() as $sub )
        {
            if( $location == 'any' || $location == 'all' || $location == $sub->name() )
            {
                if( array_search('any', $ruleTypes) !== false || array_search('security', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->securityRules, 'rules' => $sub->securityRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('nat', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->natRules, 'rules' => $sub->natRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('decryption', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->decryptionRules, 'rules' => $sub->decryptionRules->rules());
                }
                if( array_search('any', $ruleTypes) !== false || array_search('appoverride', $ruleTypes) !== false )
                {
                    $rulesToProcess[] = Array('store' => $sub->appOverrideRules, 'rules' => $sub->appOverrideRules->rules());
                }
                $locationFound = true;
            }
        }
    }

    if( !$locationFound )
    {
        print "ERROR: location '$location' was not found. Here is a list of available ones:\n";
        print " - shared\n";
        if( $configType == 'panos' )
        {
            foreach( $pan->getVirtualSystems() as $sub )
            {
                print " - ".$sub->name()."\n";
            }
        }
        else
        {
            foreach( $pan->getDeviceGroups() as $sub )
            {
                print " - ".$sub->name()."\n";
            }
        }
        print "\n\n";
        exit(1);
    }
}
// </editor-fold>


//
// It's time to process Rules !!!!
//

// <editor-fold desc="Rule Processing" defaultstate="collapsed" >
$totalObjectsProcessed = 0;
foreach( $rulesToProcess as &$rulesRecord )
{
    /** @var RuleStore $store */
    $store = $rulesRecord['store'];
    $rules = &$rulesRecord['rules'];
    $subObjectsProcessed = 0;

    foreach($doActions as $doAction )
    {
        $doAction->subSystem = $store->owner;
    }

    print "\n* processing ruleset '".$store->toString()." that holds ".count($rules)." rules\n";


    foreach($rules as $rule )
    {
        // If a filter query was input and it doesn't match this object then we simply skip it
        if( $objectFilterRQuery !== null )
        {
            $queryResult = $objectFilterRQuery->matchSingleObject(Array('object' =>$rule, 'nestedQueries'=>&$nestedQueries));
            if( !$queryResult )
                continue;
        }

        $totalObjectsProcessed++;
        $subObjectsProcessed++;

        // object will pass through every action now
        foreach( $doActions as $doAction )
        {
            $doAction->padding = '      ';
            $doAction->executeAction($rule);

            print "\n";
        }
    }

    print "* objects processed in DG/Vsys '{$store->owner->name()}' : $subObjectsProcessed filtered over {$store->count()} available\n\n";
}
print "\n";
// </editor-fold>


$first  = true;
foreach( $doActions as $doAction )
{
    if( $doAction->hasGlobalFinishAction() )
    {
        $first = false;
        $doAction->executeGlobalFinishAction();
    }
}

if( isset(PH::$args['stats']) )
{
    $pan->display_statistics();
    print "\n";
    foreach( $rulesToProcess as &$record )
    {
        if( get_class($record['store']->owner) != 'PanoramaConf' && get_class($record['store']->owner) != 'PANConf' )
        {
            $record['store']->owner->display_statistics();
            print "\n";
        }
    }
}

$totalObjectsOfSelectedStores = 0;
foreach( $rulesToProcess as &$record )
    $totalObjectsOfSelectedStores += $record['store']->count();
print "\n **** PROCESSING OF $totalObjectsProcessed OBJECTS PROCESSED over {$totalObjectsOfSelectedStores} available **** \n\n";

// save our work !!!
if( $configOutput !== null )
{
    $pan->save_to_file($configOutput);
}

print "\n\n************ END OF RULE-EDIT UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";





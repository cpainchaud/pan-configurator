<?php


RuleCallContext::$commonActionFunctions['calculate-zones'] = Array(
    'function' => function (RuleCallContext $context, $fromOrTo)
    {
        $rule = $context->object;

        $addrContainerIsNegated = false;

        $zoneContainer = null;
        $addressContainer = null;

        if( $fromOrTo == 'from' )
        {
            $zoneContainer  = $rule->from;
            $addressContainer = $rule->source;
            if( $rule->isSecurityRule() && $rule->sourceIsNegated() )
                $addrContainerIsNegated = true;
        }
        elseif( $fromOrTo == 'to' )
        {
            $zoneContainer  = $rule->to;
            $addressContainer = $rule->destination;
            if( $rule->isSecurityRule() && $rule->destinationIsNegated() )
                $addrContainerIsNegated = true;
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
                $firewall = null;
                $panorama = $system;
                if( $system->isDeviceGroup() )
                    $panorama = $system->owner;

                if( $context->arguments['template'] == $context->actionRef['args']['template']['default'] )
                    derr('with Panorama configs, you need to specify a template name');

                if( $context->arguments['virtualRouter'] == $context->actionRef['args']['virtualRouter']['default'] )
                    derr('with Panorama configs, you need to specify virtualRouter argument. Available virtual routes are: ');

                $_tmp_explTemplateName = explode('@', $context->arguments['template']);
                if( count($_tmp_explTemplateName) > 1 )
                {
                    $firewall = new PANConf();
                    $configIsOnLocalFirewall = true;
                    $doc = null;

                    if( strtolower($_tmp_explTemplateName[0]) == 'api' )
                    {
                        $panoramaConnector = findConnector($system);
                        $connector = new PanAPIConnector($panoramaConnector->apihost, $panoramaConnector->apikey, 'panos-via-panorama', $_tmp_explTemplateName[1]);
                        $firewall->connector = $connector;
                        $doc = $connector->getMergedConfig();
                        $firewall->load_from_domxml($doc);
                        unset($connector);
                    }
                    elseif( strtolower($_tmp_explTemplateName[0]) == 'file')
                    {
                        $filename = $_tmp_explTemplateName[1];
                        if( !file_exists($filename) )
                            derr("cannot read firewall configuration file '{$filename}''");
                        $doc = new DOMDocument();
                        if( ! $doc->load($filename) )
                            derr("invalive xml file".libxml_get_last_error()->message);
                        unset($filename);
                    }
                    else
                        derr("unsupported method: {$_tmp_explTemplateName[0]}@");


                    // delete rules to avoid loading all the config
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/devices/entry/vsys/entry/rulebase/*", $doc);
                    if( $deletedNodesCount === false )
                        derr("xpath issue");
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/shared/rulebase/*", $doc);
                    if( $deletedNodesCount === false )
                        derr("xpath issue");

                    //print "\n\n deleted $deletedNodesCount nodes \n\n";

                    $firewall->load_from_domxml($doc);

                    unset($deletedNodesCount);
                    unset($doc);
                }


                /** @var Template $template */
                if( !$configIsOnLocalFirewall )
                {
                    $template = $panorama->findTemplate($context->arguments['template']);
                    if ($template === null)
                        derr("cannot find Template named '{$context->arguments['template']}'. Available template list:" . PH::list_to_string($panorama->templates));
                }

                if( $configIsOnLocalFirewall )
                    $virtualRouterToProcess = $firewall->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);
                else
                    $virtualRouterToProcess = $template->deviceConfiguration->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);

                if( $virtualRouterToProcess === null )
                {
                    if( $configIsOnLocalFirewall )
                        $tmpVar = $firewall->network->virtualRouterStore->virtualRouters();
                    else
                        $tmpVar = $template->deviceConfiguration->network->virtualRouterStore->virtualRouters();

                    derr("cannot find VirtualRouter named '{$context->arguments['virtualRouter']}' in Template '{$context->arguments['template']}'. Available VR list: " . PH::list_to_string($tmpVar));
                }

                if( ( !$configIsOnLocalFirewall && count($template->deviceConfiguration->virtualSystems) == 1) || ($configIsOnLocalFirewall && count($firewall->virtualSystems) == 1))
                {
                    if( $configIsOnLocalFirewall )
                        $system = $firewall->virtualSystems[0];
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
                            $vsys = $firewall->findVirtualSystem($context->arguments['vsys']);
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

        if( $addressContainer->isAny() )
        {
            print $context->padding." - SKIPPED : address continaer is ANY()\n";
            return;
        }

        if( $rule->isSecurityRule() )
            $resolvedZones = & $addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4'], $addrContainerIsNegated );
        else
            $resolvedZones = & $addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4']);

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
            if( $addressContainer->isAny() )
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
            if( $addressContainer->isAny() )
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
    },
    'args' => Array(    'mode' => Array(    'type' => 'string',
        'default' => 'append',
        'choices' => Array('replace', 'append', 'show'),
        'help' =>   "Will determine what to do with resolved zones : show them, replace them in the rule".
            " or only append them (removes none but adds missing ones)"
    ),
        'virtualRouter' => Array(   'type' => 'string',
            'default' => '*autodetermine*',
            'help' =>   "Can optionally be provided if script cannot find which virtualRouter it should be using".
                " (ie: there are several VR in same VSYS)"
        ),
        'template' => Array(    'type' => 'string',
            'default' => '*notPanorama*',
            'help' =>   "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in".
                " such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden".
                " or if you are not using Templates then you will want load firewall config in lieu of specifying a template.".
                " \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to".
                " calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then".
                " specify file@/folderXYZ/config.xml."
        ),
        'vsys' => Array(    'type' => 'string',
            'default' => '*autodetermine*',
            'help' =>   "specify vsys when script cannot autodetermine it or when you when to manually override"
        ),
    ),
    'help' =>   "This Action will use routing tables to resolve zones. When the program cannot find all parameters by".
        " itself (like vsys or template name you will have ti manually provide them.\n\n".
        "Usage examples:\n\n".
        "    - xxx-calculate-zones\n".
        "    - xxx-calculate-zones:replace\n".
        "    - xxx-calculate-zones:append,vr1\n".
        "    - xxx-calculate-zones:replace,vr3,api@0011C890C,vsys1\n".
        "    - xxx-calculate-zones:show,vr5,Datacenter_template\n"
);

RuleCallContext::$commonActionFunctions['zone-add'] = Array(
    'function' => function (RuleCallContext $context, $fromOrTo, $force)
    {
        $rule = $context->object;

        $zoneContainer = null;

        if( $fromOrTo == 'from' )
        {
            $zoneContainer  = $rule->from;
        }
        elseif( $fromOrTo == 'to' )
        {
            $zoneContainer  = $rule->to;
        }
        else
            derr('unsupported');

        $objectFind = $zoneContainer->parentCentralStore->find($context->arguments['zoneName']);
        if ($objectFind === null && $force == false)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        $objectFind = $zoneContainer->parentCentralStore->findOrCreate($context->arguments['zoneName']);
        if ($objectFind === null)
            derr("zone named '{$context->arguments['zoneName']}' not found");

        if ($context->isAPI)
            $zoneContainer->API_addZone($objectFind);
        else
            $zoneContainer->addZone($objectFind);

    },
    'args' => Array( 'zoneName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);


/***************************************
 *
 *         Supported Actions
 *
 **************************************/
$supportedActions = Array();



// <editor-fold desc="Supported Actions Array" defaultstate="collapsed" >

//                                              //
//                Zone Based Actions            //
//                                              //
RuleCallContext::$supportedActions['from-add'] = Array(
    'name' => 'from-Add',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $f = RuleCallContext::$commonActionFunctions['zone-add']['function'];
        $f($context, 'from', false);
    },
    'args' => & RuleCallContext::$commonActionFunctions['zone-add']['args'],
);
RuleCallContext::$supportedActions['from-add-force'] = Array(
    'name' => 'from-Add-Force',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $f = RuleCallContext::$commonActionFunctions['zone-add']['function'];
        $f($context, 'from', true);
    },
    'args' => &RuleCallContext::$commonActionFunctions['zone-add']['args'],
);
RuleCallContext::$supportedActions['from-remove'] = Array(
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
RuleCallContext::$supportedActions['from-remove-force-any'] = Array(
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
RuleCallContext::$supportedActions['from-set-any'] = Array(
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

RuleCallContext::$supportedActions['to-add'] = Array(
    'name' => 'to-Add',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $f = RuleCallContext::$commonActionFunctions['zone-add']['function'];
        $f($context, 'to', false);
    },
    'args' => &RuleCallContext::$commonActionFunctions['zone-add']['args'],
);
RuleCallContext::$supportedActions['to-add-force'] = Array(
    'name' => 'to-Add-Force',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $f = RuleCallContext::$commonActionFunctions['zone-add']['function'];
        $f($context, 'to', true);
    },
    'args' => &RuleCallContext::$commonActionFunctions['zone-add']['args'],
);
RuleCallContext::$supportedActions['to-remove'] = Array(
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
RuleCallContext::$supportedActions['to-remove-force-any'] = Array(
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
RuleCallContext::$supportedActions['to-set-any'] = Array(
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

RuleCallContext::$supportedActions['from-calculate-zones'] = Array(
    'name' => 'from-calculate-zones',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $f = RuleCallContext::$commonActionFunctions['calculate-zones']['function'];
        $f($context, 'from');
    },
    'args' => & RuleCallContext::$commonActionFunctions['calculate-zones']['args'],
    'help' => & RuleCallContext::$commonActionFunctions['calculate-zones']['help']
);
RuleCallContext::$supportedActions['to-calculate-zones'] = Array(
    'name' => 'to-calculate-zones',
    'section' => 'zone',
    'MainFunction' => function(RuleCallContext $context)
    {
        $f = RuleCallContext::$commonActionFunctions['calculate-zones']['function'];
        $f($context, 'to');
    },
    'args' => & RuleCallContext::$commonActionFunctions['calculate-zones']['args'],
    'help' => & RuleCallContext::$commonActionFunctions['calculate-zones']['help']
);


//                                                    //
//                Source/Dest Based Actions           //
//                                                    //
RuleCallContext::$supportedActions['src-add'] = Array(
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
RuleCallContext::$supportedActions['src-remove'] = Array(
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
RuleCallContext::$supportedActions['src-remove-force-any'] = Array(
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
RuleCallContext::$supportedActions['dst-add'] = Array(
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
RuleCallContext::$supportedActions['dst-remove'] = Array(
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
RuleCallContext::$supportedActions['dst-remove-force-any'] = Array(
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
RuleCallContext::$supportedActions['src-set-any'] = Array(
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
RuleCallContext::$supportedActions['dst-set-any'] = Array(
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
RuleCallContext::$supportedActions['tag-add'] = Array(
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
RuleCallContext::$supportedActions['tag-add-force'] = Array(
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
RuleCallContext::$supportedActions['tag-remove'] = Array(
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
RuleCallContext::$supportedActions['tag-remove-regex'] = Array(
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
RuleCallContext::$supportedActions['service-set-appdefault'] = Array(
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
RuleCallContext::$supportedActions['service-set-any'] = Array(
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
RuleCallContext::$supportedActions['service-add'] = Array(
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
            $rule->services->add($objectFind);
    },
    'args' => Array( 'svcName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
RuleCallContext::$supportedActions['service-remove'] = Array(
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
RuleCallContext::$supportedActions['service-remove-force-any'] = Array(
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
RuleCallContext::$supportedActions['app-set-any'] = Array(
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
RuleCallContext::$supportedActions['app-add'] = Array(
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
RuleCallContext::$supportedActions['app-remove'] = Array(
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
RuleCallContext::$supportedActions['app-remove-force-any'] = Array(
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
RuleCallContext::$supportedActions['logstart-enable'] = Array(
    'name' => 'logStart-Enable',
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
RuleCallContext::$supportedActions['logstart-disable'] = Array(
    'name' => 'logStart-Disable',
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
RuleCallContext::$supportedActions['logstart-enable-fastapi'] = Array(
    'name' => 'logStart-Enable-FastAPI',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$context->isAPI )
            derr("only supported in API mode!");

        if( $rule->setLogStart(true) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<log-start>yes</log-start>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $context->doBundled_API_Call();
    },
);
RuleCallContext::$supportedActions['logstart-disable-fastapi'] = Array(
    'name' => 'logStart-Disable-FastAPI',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$context->isAPI )
            derr("only supported in API mode!");

        if( $rule->setLogStart(false) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<log-start>no</log-start>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $context->doBundled_API_Call();
    },
);
RuleCallContext::$supportedActions['logstart-enable-fastapi'] = Array(
    'name' => 'logStart-Enable-FastAPI',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$context->isAPI )
            derr("only supported in API mode!");

        if( $rule->setLogStart(true) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<log-start>yes</log-start>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $context->doBundled_API_Call();
    },
);
RuleCallContext::$supportedActions['logend-enable'] = Array(
    'name' => 'logEnd-Enable',
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

RuleCallContext::$supportedActions['logend-Disable'] = Array(
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
RuleCallContext::$supportedActions['logend-disable-fastapi'] = Array(
    'name' => 'logend-Disable-FastAPI',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$context->isAPI )
            derr("only supported in API mode!");

        if( $rule->setLogEnd(false) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<log-end>no</log-end>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $context->doBundled_API_Call();
    },
);
RuleCallContext::$supportedActions['logend-enable-fastapi'] = Array(
    'name' => 'logend-Enable-FastAPI',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$context->isAPI )
            derr("only supported in API mode!");

        if( $rule->setLogEnd(true) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<log-end>yes</log-end>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $context->doBundled_API_Call();
    },
);
RuleCallContext::$supportedActions['logsetting-set'] = Array(
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
//                Security profile Based Actions     //
//                                                   //
RuleCallContext::$supportedActions['securityprofile-group-set'] = Array(
    'name' => 'securityProfile-Group-Set',
    'MainFunction' =>  function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
        {
            print $context->padding."  - SKIPPED : this is not a Security rule\n";
            return;
        }

        if( $context->isAPI )
            $rule->API_setSecurityProfileGroup($context->arguments['profName']);
        else
            $rule->setSecurityProfileGroup($context->arguments['profName']);
    },
    'args' => Array( 'profName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) )
);
RuleCallContext::$supportedActions['securityprofile-remove'] = Array(
    'name' => 'securityProfile-Remove',
    'MainFunction' =>  function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
        {
            print $context->padding."  - SKIPPED : this is not a Security rule\n";
            return;
        }

        if( $context->isAPI )
            $rule->API_removeSecurityProfile();
        else
            $rule->removeSecurityProfile();
    },
);
RuleCallContext::$supportedActions['securityprofile-group-set-fastapi'] = Array(
    'name' => 'securityProfile-Group-Set-FastAPI',
    'section' => 'log',
    'MainFunction' => function(RuleCallContext $context)
    {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
        {
            print $context->padding." - SKIPPED : this is not a Security rule\n";
            return;
        }

        if( !$context->isAPI )
            derr("only supported in API mode!");

        if( $rule->setSecurityProfileGroup($context->arguments['profName']) )
        {
            print $context->padding." - QUEUED for bundled API call\n";
            $context->addRuleToMergedApiChange('<profile-setting><group><member>' . $context->arguments['profName'] . '</member></group></profile-setting>');
        }
    },
    'GlobalFinishFunction' => function(RuleCallContext $context)
    {
        $context->doBundled_API_Call();
    },
);

RuleCallContext::$supportedActions['description-append'] = Array(
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
RuleCallContext::$supportedActions['enabled-set'] = Array(
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
RuleCallContext::$supportedActions['enabled-set-fastapi'] = Array(
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
        $context->doBundled_API_Call();
    },
    'args' => Array(    'trueOrFalse' => Array( 'type' => 'bool', 'default' => 'yes'  ) )
);
RuleCallContext::$supportedActions['disabled-set'] = Array(
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
RuleCallContext::$supportedActions['disabled-set-fastapi'] = Array(
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
RuleCallContext::$supportedActions['delete'] = Array(
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
RuleCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function(RuleCallContext $context) { $context->object->display(7); }
);
RuleCallContext::$supportedActions['invertpreandpost'] = Array(
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


RuleCallContext::$supportedActions['copy'] = Array(
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
            if( $pan->isFirewall() )
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

RuleCallContext::$supportedActions['exporttoexcel'] = Array(
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
            $output = '';

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

            return "<td>{$output}</td>";
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

                if ($rule->owner->owner->isPanorama() || $rule->owner->owner->isFirewall())
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

        $content = file_get_contents(dirname(__FILE__).'/html-export-template.html');
        $content = str_replace('%TableHeaders%',
            '<th>location</th><th>type</th><th>name</th><th>from</th><th>src</th><th>to</th><th>dst</th><th>service</th><th>application</th>'.
            '<th>action</th><th>log start</th><th>log end</th><th>disabled</th><th>description</th>'.
            '<th>SNAT type</th><th>SNAT hosts</th><th>DNAT host</th><th>DNAT port</th>',
            $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent =  file_get_contents(dirname(__FILE__).'/jquery-1.11.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__).'/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    },
    'args' => Array(    'filename' => Array( 'type' => 'string', 'default' => '*nodefault*'  ) )
);

RuleCallContext::$supportedActions['cloneforappoverride'] = Array(
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
/************************************ */




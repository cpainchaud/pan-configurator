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
print   "*********** SERVICE-EDIT UTILITY **************\n\n";


set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__).'/../');
require_once("lib/panconfigurator.php");
require_once("common/actions.php");


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

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = false;
$objectsLocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = false;



$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['listactions'] = Array('niceName' => 'ListActions', 'shortHelp' => 'lists available Actions');
$supportedArguments['listfilters'] = Array('niceName' => 'ListFilters', 'shortHelp' => 'lists available Filters');
$supportedArguments['stats'] = Array('niceName' => 'Stats', 'shortHelp' => 'display stats after changes');
$supportedArguments['actions'] = Array('niceName' => 'Actions', 'shortHelp' => 'action to apply on each rule matched by Filter. ie: actions=from-Add:net-Inside,netDMZ', 'argDesc' => 'action:arg1[,arg2]' );
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['filter'] = Array('niceName' => 'Filter', 'shortHelp' => "filters objects based on a query. ie: 'filter=((from has external) or (source has privateNet1) and (to has external))'", 'argDesc' => '(field operator [value])');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');


//
// Supported Actions
//
$supportedActions = Array();
// <editor-fold desc="  ****  Supported Actions Array  ****" defaultstate="collapsed" >


$supportedActions['delete'] = Array(
    'name' => 'delete',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0)
            derr("this object is used by other objects and cannot be deleted (use 'deleteForce' to try anyway or 'replaceWithObject')");
        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

$supportedActions['deleteforce'] = Array(
    'name' => 'deleteForce',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

$supportedActions['addobjectwhereused'] = Array(
    'name' => 'addObjectWhereUsed',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        $clearForAction = true;
        foreach ($objectRefs as $objectRef)
        {
            $class = get_class($objectRef);
            if ($class != 'ServiceRuleContainer' && $class != 'ServiceGroup')
            {
                $clearForAction = false;
                print "     *  skipped because its used in unsupported class $class\n";
                break;
            }
        }
        if( $clearForAction )
        {
            foreach ($objectRefs as $objectRef)
            {
                $class = get_class($objectRef);
                if ($class == 'ServiceRuleContainer' || $class == 'ServiceGroup')
                {
                    print $context->padding." - adding in {$objectRef->toString()}\n";
                    if( $context->isAPI )
                        $objectRef->API_add($foundObject);
                    else
                        $objectRef->add($foundObject);
                } else
                {
                    derr('unsupported class');
                }

            }
        }
    },
    'args' => Array( 'objectName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);

$supportedActions['replacewithobject'] = Array(
    'name' => 'replaceWithObject',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        /** @var $objectRef ServiceGroup|ServiceRuleContainer */

        foreach ($objectRefs as $objectRef)
        {
            print $context->padding." * replacing in {$objectRef->toString()}\n";
            if( $context->isAPI )
                $objectRef->API_replaceReferencedObject($object, $foundObject);
            else
                $objectRef->replaceReferencedObject($object, $foundObject);
        }

    },
    'args' => Array( 'objectName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);

$supportedActions['exporttoexcel'] = Array(
    'name' => 'exportToExcel',
    'MainFunction' => function(ServiceCallContext $context)
    {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function(ServiceCallContext $context)
    {
        $context->objectList = Array();
    },
    'GlobalFinishFunction' => function(ServiceCallContext $context)
    {
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
        if( isset($context->objectList) )
        {
            foreach ($context->objectList as $object)
            {
                $count++;

                /** @var Service|ServiceGroup $object */
                if ($count % 2 == 1)
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                if ($object->owner->owner->isPanorama() || $object->owner->owner->isFirewall())
                    $lines .= $encloseFunction('shared');
                else
                    $lines .= $encloseFunction($object->owner->owner->name());

                $lines .= $encloseFunction($object->name());

                if( $object->isGroup() )
                {
                        $lines .= $encloseFunction('group');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction($object->members());
                }
                elseif ( $object->isService() )
                {
                    if( $object->isTmpSrv() )
                        $lines .= $encloseFunction('unknown');
                    else
                    {
                        if( $object->isTcp() )
                            $lines .= $encloseFunction('service-tcp');
                        else
                            $lines .= $encloseFunction('service-udp');

                        $lines .= $encloseFunction($object->getDestPort());
                        $lines .= $encloseFunction($object->getSourcePort());
                    }

                    $lines .= $encloseFunction($object->description(), false);
                }

                $lines .= "</tr>\n";
            }
        }

        $content = file_get_contents(dirname(__FILE__).'/common/html-export-template.html');
        $content = str_replace('%TableHeaders%',
                                '<th>location</th><th>name</th><th>type</th><th>dport</th><th>sport</th><th>members</th><th>description</th>',
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


$supportedActions['move'] = Array(
    'name' => 'move',
    'MainFunction' =>  function ( ServiceCallContext $context )
    {
        $object = $context->object;

        $localLocation = 'shared';

        if( ! $object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            print $context->padding."   * SKIPPED because original and target destinations are the same: $targetLocation\n";
            return;
        }

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $targetLocation == 'shared' )
        {
            $targetStore = $rootObject->serviceStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->serviceStore;
        }

        if( $localLocation == 'shared' )
        {
            print $context->padding."   * SKIPPED : moving from SHARED to sub-level is not yet supported\n";
            return;
        }

        if( $localLocation != 'shared' && $targetLocation != 'shared' )
        {
            print $context->padding."   * SKIPPED : moving between 2 VSYS/DG is not supported yet\n";
            return;
        }

        $conflictObject = $targetStore->find($object->name() ,null, false);
        if( $conflictObject === null )
        {
            print $context->padding."   * moved, no conflict\n";
            if( $context->isAPI )
            {
                derr("unsupported with API yet");
            }
            else
            {
                $object->owner->remove($object);
                $targetStore->add($object);
            }
            return;
        }

        if( $context->arguments['mode'] == 'skipifconflict' )
        {
            print $context->padding."   * SKIPPED : there is an object with same name. Choose another mode to to resolve this conflict\n";
            return;
        }

        print $context->padding."   - there is a conflict with type ";
        if( $conflictObject->isGroup() )
            print "Group\n";
        else
            print "Service\n";

        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            print $context->padding."   * SKIPPED because conflict has mismatching types\n";
            return;
        }

        if( $conflictObject->isTmpSrv() && !$object->isTmpSrv() )
        {
            derr("unsupported situation with a temporary object");
            return;
        }

        if( $object->isTmpSrv() )
        {
            print $context->padding."   * SKIPPED because this object is Tmp\n";
            return;
        }

        if( $object->isGroup() )
        {
            if( $object->equals($conflictObject) )
            {
                print "    * Removed because target has same content\n";
                goto do_replace;
            }
            else
            {
                $object->displayValueDiff($conflictObject, 9);
                if( $context->arguments['mode'] == 'removeifmatch')
                {
                    print $context->padding."    * SKIPPED because of mismatching group content\n";
                    return;
                }

                $localMap = $object->dstPortMapping();
                $targetMap = $conflictObject->dstPortMapping();

                if( ! $localMap->equals($targetMap) )
                {
                    print $context->padding."    * SKIPPED because of mismatching group content and numerical values\n";
                    return;
                }

                print "    * Removed because it has same numerical value\n";

                goto do_replace;

            }
            return;
        }

        if( $object->equals($conflictObject) )
        {
            print "    * Removed because target has same content\n";
            goto do_replace;
        }

        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $localMap = $object->dstPortMapping();
        $targetMap = $conflictObject->dstPortMapping();

        if( ! $localMap->equals($targetMap) )
        {
            print $context->padding."    * SKIPPED because of mismatching content and numerical values\n";
            return;
        }

        print "    * Removed because target has same numerical value\n";

        do_replace:

        $object->replaceMeGlobally($conflictObject);
        if($context->isAPI)
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);


    },
    'args' => Array( 'location' => Array( 'type' => 'string', 'default' => '*nodefault*' ),
        'mode' => Array( 'type' => 'string', 'default' => 'skipIfConflict', 'choices' => Array( 'skipIfConflict', 'removeIfMatch', 'removeIfNumericalMatch') )
    ),
);

$supportedActions['removewhereused'] = Array(
    'name' => 'removeWhereUsed',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $context->isAPI )
            $object->API_removeWhereIamUsed(true, $context->padding, $context->arguments['actionIfLastMemberInRule']);
        else
            $object->removeWhereIamUsed(true, $context->padding, $context->arguments['actionIfLastMemberInRule']);
    },
    'args' => Array( 'actionIfLastMemberInRule' => Array(   'type' => 'string',
                                                            'default' => 'delete',
                                                            'choices' => Array( 'delete', 'disable', 'setAny' )
                                                        ),
    ),
);

$supportedActions['replacegroupbyservice'] = Array(
    'name' => 'replaceGroupByService',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $context->isAPI )
            derr("action 'replaceGroupByService' is not support in API/online mode yet");

        if( $object->isService() )
        {
            print $context->padding." *** SKIPPED : this is not a group\n";
            return;
        }
        if( !$object->isGroup() )
        {
            print $context->padding." *** SKIPPED : unsupported object type\n";
            return;
        }
        if( $object->count() < 1 )
        {
            print $context->padding." *** SKIPPED : group has no member\n";
            return;
        }

        $mapping = $object->dstPortMapping();
        if( $mapping->hasTcpMappings() && $mapping->hasUdpMappings() )
        {
            print $context->padding." *** SKIPPED : group has a mix of UDP and TCP based mappings, they cannot be merged in a single object\n";
            return;
        }


        $store = $object->owner;

        $store->remove($object);

        if( $mapping->hasUdpMappings() )
            $newService = $store->newService($object->name(), 'udp', $mapping->udpMappingToText() );
        else
            $newService = $store->newService($object->name(), 'tcp', $mapping->tcpMappingToText() );

        $object->replaceMeGlobally($newService);

        if( $mapping->hasUdpMappings() )
            print $context->padding." * replaced by service with same name and value: udp/{$newService->dstPortMapping()->udpMappingToText()}\n";
        else
            print $context->padding." * replaced by service with same name and value: tcp/{$newService->dstPortMapping()->tcpMappingToText()}\n";

    },
);

$supportedActions['replacebymembersanddelete'] = Array(
    'name' => 'replaceByMembersAndDelete',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;


        if( !$object->isGroup() )
        {
            print $context->padding."     *  skipped it's not a group\n";
            return;
        }


        $objectRefs = $object->getReferences();

        $clearForAction = true;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'ServiceRuleContainer' && $class != 'ServiceGroup' )
            {
                $clearForAction = false;
                print "     *  skipped because its used in unsupported class $class\n";
                return;
            }
        }
        if( $clearForAction )
        {
            foreach ($objectRefs as $objectRef)
            {
                $class = get_class($objectRef);
                if ($class == 'ServiceRuleContainer' || $class == 'ServiceGroup')
                {
                    print $context->padding."    - in Reference: {$objectRef->toString()}\n";
                    /** @var ServiceRuleContainer|ServiceGroup $objectRef */
                    foreach ($object->members() as $objectMember)
                    {
                        print $context->padding."      - adding {$objectMember->name()}\n";
                        if( $context->isAPI )
                            $objectRef->API_add($objectMember);
                        else
                            $objectRef->add($objectMember);
                    }
                    if( $context->isAPI )
                        $objectRef->API_remove($object);
                    else
                        $objectRef->remove($object);
                } else
                {
                    derr('unsupported class');
                }

            }
            if( $context->isAPI )
                $object->owner->API_remove($object, true);
            else
                $object->owner->remove($object, true);
        }
    },
);

$supportedActions['name-addprefix'] = Array(
    'name' => 'name-addPrefix',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;
        $newName = $context->arguments['prefix'].$object->name();
        print $context->padding." - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            print " *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, false) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, true) !== null   )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => Array( 'prefix' => Array( 'type' => 'string', 'default' => '*nodefault*' )
    ),
);
$supportedActions['name-addsuffix'] = Array(
    'name' => 'name-addSuffix',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;
        $newName = $object->name().$context->arguments['suffix'];
        print $context->padding." - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            print " *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, false) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, true) !== null   )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else
            $object->setName($newName);
    },
    'args' => Array( 'suffix' => Array( 'type' => 'string', 'default' => '*nodefault*' )
    ),
);


$supportedActions['displayreferences'] = Array(
    'name' => 'displayReferences',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        $object->display_references(7);
    },
);

$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;
        print "     * ".get_class($object)." '{$object->name()}' \n";
        if( $object->isGroup() ) foreach($object->members() as $member) print "          - {$member->name()}\n";
                print "\n\n";
    },
);
// </editor-fold>



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
    ksort(RQuery::$defaultFilters['service']);

    print "Listing of supported filters:\n\n";

    foreach(RQuery::$defaultFilters['service'] as $index => &$filter )
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
    $objectsFilter = PH::$args['filter'];
    if( !is_string($objectsFilter) || strlen($objectsFilter) < 1 )
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
// </editor-fold>



//
// Location provided in CLI ?
//
if( isset(PH::$args['location'])  )
{
    $objectsLocation = PH::$args['location'];
    if( !is_string($objectsLocation) || strlen($objectsLocation) < 1 )
        display_error_usage_exit('"location" argument is not a valid string');
}
else
{
    if( $configType == 'panos' )
    {
        print " - No 'location' provided so using default ='vsys1'\n";
        $objectsLocation = 'vsys1';
    }
    else
    {
        print " - No 'location' provided so using default ='shared'\n";
        $objectsLocation = 'shared';
    }
}


//
// Extracting actions
//
$explodedActions = explode('/', $doActions);
/** @var ServiceCallContext[] $doActions */
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

    $context = new ServiceCallContext($supportedActions[$actionName], $explodedAction[1]);
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
if( $objectsFilter !== null )
{
    $objectFilterRQuery = new RQuery('service');
    $res = $objectFilterRQuery->parseFromString($objectsFilter, $errorMessage);
    if( $res === false )
    {
        fwrite(STDERR, "\n\n**ERROR** Rule filter parser: " . $errorMessage . "\n\n");
        exit(1);
    }

    print " - filter after sanitization : ".$objectFilterRQuery->sanitizedString()."\n";
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

// <editor-fold desc=" ****  Location Filter Processing  ****" defaultstate="collapsed" >
/**
 * @var RuleStore[] $ruleStoresToProcess
 */
$objectsLocation = explode(',', $objectsLocation);

foreach( $objectsLocation as &$location )
{
    if( strtolower($location) == 'shared' )
        $location = 'shared';
    else if( strtolower($location) == 'any' )
        $location = 'any';
    else if( strtolower($location) == 'all' )
        $location = 'any';
}
$objectsLocation = array_unique($objectsLocation);

$objectsToProcess = Array();

foreach( $objectsLocation as $location )
{
    $locationFound = false;

    if( $configType == 'panos')
    {
        if( $location == 'shared' || $location == 'any'  )
        {
            $objectsToProcess[] = Array('store' => $pan->serviceStore, 'objects' => $pan->serviceStore->all());
            $locationFound = true;
        }
        foreach ($pan->getVirtualSystems() as $sub)
        {
            if( ($location == 'any' || $location == 'all' || $location == $sub->name() && !isset($ruleStoresToProcess[$sub->name()]) ))
            {
                $objectsToProcess[] = Array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all());
                $locationFound = true;
            }
        }
    }
    else
    {
        if( $location == 'shared' || $location == 'any' )
        {

            $objectsToProcess[] = Array('store' => $pan->serviceStore, 'objects' => $pan->serviceStore->all());
            $locationFound = true;
        }

        foreach( $pan->getDeviceGroups() as $sub )
        {
            if( ($location == 'any' || $location == 'all' || $location == $sub->name()) && !isset($ruleStoresToProcess[$sub->name().'%pre']) )
            {
                $objectsToProcess[] = Array('store' => $sub->serviceStore, 'objects' => $sub->serviceStore->all() );
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

// <editor-fold desc=" *****  Object Processing  *****" defaultstate="collapsed" >

$totalObjectsProcessed = 0;

foreach( $objectsToProcess as &$objectsRecord )
{
    $subObjectsProcessed = 0;

    /** @var ServiceStore $store */
    $store = $objectsRecord['store'];
    $objects = &$objectsRecord['objects'];
    foreach( $doActions as $doAction )
    {
        $doAction->subSystem = $store->owner;
    }

    print "\n* processing store '".PH::boldText($store->toString())." that holds ".PH::boldText(count($objects))." objects\n";


    foreach($objects as $object )
    {
        if( $objectFilterRQuery !== null )
        {
            $queryResult = $objectFilterRQuery->matchSingleObject($object);
            if( !$queryResult )
                continue;
        }

        $totalObjectsProcessed++;
        $subObjectsProcessed++;

        //mwarning($object->name());

        foreach( $doActions as $doAction )
        {
            $doAction->padding = '     ';
            $doAction->executeAction($object);

            print "\n";
        }
    }

    print "* objects processed in DG/Vsys '{$store->owner->name()}' : $subObjectsProcessed\n\n";
}
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

print "\n **** PROCESSING OF $totalObjectsProcessed OBJECTS DONE **** \n\n";

if( isset(PH::$args['stats']) )
{
    $pan->display_statistics();
    print "\n";
    foreach( $objectsToProcess as &$record )
    {
        if( get_class($record['store']->owner) != 'PanoramaConf' && get_class($record['store']->owner) != 'PANConf' )
        {
            $record['store']->owner->display_statistics();
            print "\n";
        }
    }
}


// save our work !!!
if( $configOutput !== null )
{
    if( $configOutput != '/dev/null' )
    {
        $pan->save_to_file($configOutput);
    }
}


print "\n\n*********** END OF SERVICE-EDIT UTILITY **********\n";
print     "**************************************************\n";
print "\n\n";





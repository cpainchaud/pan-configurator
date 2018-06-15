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


ServiceCallContext::$supportedActions[] = Array(
    'name' => 'delete',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding."  * SKIPPED: this object is used by other objects and cannot be deleted (use deleteForce to try anyway)\n";
            return;
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'deleteForce',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0 )
            print $context->padding."  * WARNING : this object seems to be used so deletion may fail.\n";

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

ServiceCallContext::$supportedActions[] = Array(
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

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'replaceWithObject',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        /** @var ServiceGroup|ServiceRuleContainer $objectRef */

        foreach ($objectRefs as $objectRef)
        {
            print $context->padding." * replacing in {$objectRef->toString()}\n";
            if( $objectRef === $foundObject || $objectRef->name() == $foundObject->name() )
            {
                print $context->padding."   - SKIPPED : cannot replace an object by itself\n";
                continue;
            }
            if( $context->isAPI )
                $objectRef->API_replaceReferencedObject($object, $foundObject);
            else
                $objectRef->replaceReferencedObject($object, $foundObject);
        }

    },
    'args' => Array( 'objectName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);

ServiceCallContext::$supportedActions[] = Array(
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


        $addWhereUsed = false;
        $addUsedInLocation = false;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = true;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = true;


        $headers = '<th>location</th><th>name</th><th>type</th><th>dport</th><th>sport</th><th>members</th><th>description</th><th>tags</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

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

                $lines .= $encloseFunction(PH::getLocationString($object));

                $lines .= $encloseFunction($object->name());

                if( $object->isGroup() )
                {
                    $lines .= $encloseFunction('group');
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction($object->members());
                    $lines .= $encloseFunction('');
                    $lines .= $encloseFunction($object->tags->tags());
                }
                elseif ( $object->isService() )
                {
                    if( $object->isTmpSrv() )
                    {
                        $lines .= $encloseFunction('unknown');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                    }
                    else
                    {
                        if( $object->isTcp() )
                            $lines .= $encloseFunction('service-tcp');
                        else
                            $lines .= $encloseFunction('service-udp');

                        $lines .= $encloseFunction($object->getDestPort());
                        $lines .= $encloseFunction($object->getSourcePort());
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction($object->description(), false);
                        $lines .= $encloseFunction($object->tags->tags());
                    }
                }

                if( $addWhereUsed )
                {
                    $refTextArray = Array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = Array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $encloseFunction($refTextArray);
                }

                $lines .= "</tr>\n";
            }
        }

        $content = file_get_contents(dirname(__FILE__).'/html-export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent =  file_get_contents(dirname(__FILE__).'/jquery-1.11.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__).'/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    },
    'args' => Array(    'filename' => Array( 'type' => 'string', 'default' => '*nodefault*' ),
        'additionalFields' =>
            Array( 'type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => Array('WhereUsed', 'UsedInLocation'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n".
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n".
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n")
    )
);

// TODO replaceByApp with file list

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'move',
    'MainFunction' =>  function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpSrv() )
        {
            print $context->padding."   * SKIPPED because this object is Tmp\n";
            return;
        }

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
            if( $object->isGroup() )
            {
                foreach($object->members() as $memberObject)
                    if( $targetStore->find($memberObject->name()) === NULL )
                    {
                        echo $context->padding."   * SKIPPED : this group has an object named '{$memberObject->name()} that does not exist in target location '{$targetLocation}'\n";
                        return;
                    }
            }

            print $context->padding."   * moved, no conflict\n";
            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->remove($object);
                $targetStore->add($object);
                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
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

        print $context->padding."   - there is a conflict with an object of same name and type. Please use service-merger.php script with argument 'allowmergingwithupperlevel'";
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

ServiceCallContext::$supportedActions[] = Array(
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

ServiceCallContext::$supportedActions[] = Array(
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

        foreach( $object->members() as $member )
        {
            if( $member->isTmpSrv() )
            {
                print $context->padding." *** SKIPPED : temporary services detected\n";
                return;
            }
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

ServiceCallContext::$supportedActions[] = Array(
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
                if( $class == 'ServiceRuleContainer' )
                {
                    /** @var ServiceRuleContainer $objectRef */

                    print $context->padding."    - in Reference: {$objectRef->toString()}\n";
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
                }
                elseif( $class == 'ServiceGroup' )
                {
                    /** @var ServiceGroup $objectRef */

                    print $context->padding."    - in Reference: {$objectRef->toString()}\n";
                    foreach ($object->members() as $objectMember)
                    {
                        print $context->padding."      - adding {$objectMember->name()}\n";
                        if( $context->isAPI )
                            $objectRef->API_addMember($objectMember);
                        else
                            $objectRef->addMember($objectMember);
                    }
                    if( $context->isAPI )
                        $objectRef->API_removeMember($object);
                    else
                        $objectRef->removeMember($object);
                }
                else
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

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'name-addPrefix',
    'MainFunction' =>  function ( ServiceCallContext $context )
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
ServiceCallContext::$supportedActions[] = Array(
    'name' => 'name-addSuffix',
    'MainFunction' =>  function ( ServiceCallContext $context )
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
ServiceCallContext::$supportedActions[] = Array(
    'name' => 'name-removePrefix',
    'MainFunction' =>  function ( ServiceCallContext $context )
    {
        $object = $context->object;
        $prefix = $context->arguments['prefix'];

        if( strpos($object->name(), $prefix) !== 0 )
        {
            echo $context->padding." *** SKIPPED : prefix not found\n";
            return;
        }
        $newName = substr($object->name(), strlen($prefix));

        if ( !preg_match("/^[a-zA-Z0-9]/", $newName[0]) )
        {
            echo $context->padding." *** SKIPPED : object name contains not allowed character at the beginning\n";
            return;
        }

        echo $context->padding." - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, false) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, true) !== null   )
        {
            echo $context->padding." *** SKIPPED : an object with same name already exists\n";
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
ServiceCallContext::$supportedActions[] = Array(
    'name' => 'name-removeSuffix',
    'MainFunction' =>  function ( ServiceCallContext $context )
    {
        $object = $context->object;
        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( substr($object->name(), $suffixStartIndex, strlen($object->name()) ) != $suffix )
        {
            echo $context->padding." *** SKIPPED : suffix not found\n";
            return;
        }
        $newName = substr( $object->name(), 0, $suffixStartIndex );

        echo $context->padding." - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, false) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, true) !== null   )
        {
            echo $context->padding." *** SKIPPED : an object with same name already exists\n";
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

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'name-Rename',
    'MainFunction' =>  function ( ServiceCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpSrv() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }
        if( $object->isGroup() )
        {
            echo $context->padding." *** SKIPPED : not applicable to Group objects\n";
            return;
        }

        $newName = $context->arguments['stringFormula'];

        if( strpos($newName, '$$current.name$$') !== FALSE )
        {
            $newName = str_replace('$$current.name$$', $object->name(), $newName);
        }
        if( strpos( $newName, '$$value$$' ) !== FALSE )
        {
            $newName = str_replace( '$$value$$', $object->value(), $newName);
        }


        if( strpos( $newName, '$$protocol$$' ) !== FALSE )
        {
            $newName = str_replace( '$$protocol$$', $object->protocol(), $newName);
        }
        if( strpos( $newName, '$$destinationport$$' ) !== FALSE )
        {
            $newName = str_replace( '$$destinationport$$', $object->getDestPort(), $newName);
        }
        if( strpos( $newName, '$$sourceport$$' ) !== FALSE )
        {
            $newName = str_replace( '$$sourceport$$', $object->getSourcePort(), $newName);
        }



        if( $object->name() == $newName )
        {
            echo $context->padding." *** SKIPPED : new name and old name are the same\n";
            return;
        }

        echo $context->padding." - new name will be '{$newName}'\n";

        $findObject = $object->owner->find($newName);
        if( $findObject !== null )
        {
            echo $context->padding." *** SKIPPED : an object with same name already exists\n";
            return;
        }
        else
        {
            echo $context->padding." - renaming object... ";
            if( $context->isAPI )
                $object->API_setName($newName);
            else
                $object->setName($newName);
            echo "OK!\n";
        }

    },
    'args' => Array( 'stringFormula' => Array(
        'type' => 'string',
        'default' => '*nodefault*',
        'help' =>
            "This string is used to compose a name. You can use the following aliases :\n".
            "  - \\$\$current.name\\$\\$ : current name of the object\n".
            "  - \\$\$destinationport\\$\\$ : destination Port\n".
            "  - \\$\$protocol\\$\\$ : service protocol\n".
            "  - \\$\$sourceport\\$\\$ : source Port\n".
            "  - \\$\$value\\$\\$ : value of the object\n"
    )
    ),
    'help' => ''
);

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'displayReferences',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;

        $object->display_references(7);
    },
);

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'display',
    'MainFunction' => function ( ServiceCallContext $context )
    {
        $object = $context->object;
        print "     * ".get_class($object)." '{$object->name()}'    ";
        if( $object->isGroup() )
        {
            print "\n";
            foreach($object->members() as $member)
            {
                if( $object->isGroup() )
                    print "          - {$member->name()}\n";
                else
                    print "          - {$member->name()}   desc: '{$member->description()}'\n";
            }

        }
        else
            print "value: '{$object->protocol()}/{$object->getDestPort()}'    desc: '{$object->description()}'\n";

        print "\n\n";
    },
);

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'tag-Add',
    'section' => 'tag',
    'MainFunction' => function(ServiceCallContext $context)
    {
        $object = $context->object;
        $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $object->tags->API_addTag($objectFind);
        else
            $object->tags->addTag($objectFind);
    },
    'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
ServiceCallContext::$supportedActions[] = Array(
    'name' => 'tag-Add-Force',
    'section' => 'tag',
    'MainFunction' => function(ServiceCallContext $context)
    {
        $object = $context->object;
        if( $context->isAPI )
        {
            $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
            if( $objectFind === null)
                $objectFind = $object->tags->parentCentralStore->API_createTag($context->arguments['tagName']);
        }
        else
            $objectFind = $object->tags->parentCentralStore->findOrCreate($context->arguments['tagName']);

        if( $context->isAPI )
            $object->tags->API_addTag($objectFind);
        else
            $object->tags->addTag($objectFind);
    },
    'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
ServiceCallContext::$supportedActions[] = Array(
    'name' => 'tag-Remove',
    'section' => 'tag',
    'MainFunction' => function(ServiceCallContext $context)
    {
        $object = $context->object;
        $objectFind = $object->tags->parentCentralStore->find($context->arguments['tagName']);
        if( $objectFind === null )
            derr("tag named '{$context->arguments['tagName']}' not found");

        if( $context->isAPI )
            $object->tags->API_removeTag($objectFind);
        else
            $object->tags->removeTag($objectFind);
    },
    'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
ServiceCallContext::$supportedActions[] = Array(
    'name' => 'tag-Remove-All',
    'section' => 'tag',
    'MainFunction' => function(ServiceCallContext $context)
    {
        $object = $context->object;
        foreach($object->tags->tags() as $tag )
        {
            echo $context->padding."  - removing tag {$tag->name()}... ";
            if( $context->isAPI )
                $object->tags->API_removeTag($tag);
            else
                $object->tags->removeTag($tag);
            echo "OK!\n";
        }
    },
    //'args' => Array( 'tagName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
ServiceCallContext::$supportedActions[] = Array(
    'name' => 'tag-Remove-Regex',
    'section' => 'tag',
    'MainFunction' => function(ServiceCallContext $context)
    {
        $object = $context->object;
        $pattern = '/'.$context->arguments['regex'].'/';
        foreach($object->tags->tags() as $tag )
        {
            $result = preg_match($pattern, $tag->name());
            if( $result === false )
                derr("'$pattern' is not a valid regex");
            if( $result == 1 )
            {
                echo $context->padding."  - removing tag {$tag->name()}... ";
                if( $context->isAPI )
                    $object->tags->API_removeTag($tag);
                else
                    $object->tags->removeTag($tag);
                echo "OK!\n";
            }
        }
    },
    'args' => Array( 'regex' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);

ServiceCallContext::$supportedActions[] = Array(
    'name' => 'description-Append',
    'MainFunction' =>  function(ServiceCallContext $context)
    {
        $service = $context->object;
        if( $service->isGroup())
        {
            echo $context->padding." *** SKIPPED : a service group has no description\n";
            return;
        }
        if( $service->isTmpSrv() )
        {
            echo $context->padding." *** SKIPPED : object is tmp\n";
            return;
        }
        $description = $service->description();

        $textToAppend = "";
        if( $description != "" )
            $textToAppend = " ";
        $textToAppend .= $context->rawArguments['text'];

        if( strlen($description) + strlen($textToAppend) > 253 )
        {
            echo $context->padding." - SKIPPED : resulting description is too long\n";
            return;
        }

        echo $context->padding." - new description will be: '{$description}{$textToAppend}' ... ";

        if( $context->isAPI )
            $service->API_setDescription($description.$textToAppend);
        else
            $service->setDescription($description.$textToAppend);

        echo "OK";
    },
    'args' => Array( 'text' => Array( 'type' => 'string', 'default' => '*nodefault*' ))
);

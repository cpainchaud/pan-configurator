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



AddressCallContext::$supportedActions[] = Array(
    'name' => 'delete',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding."  * SKIPPED: this object is used by other objects and cannot be deleted (use delete-Force to try anyway)\n";
            return;
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'delete-Force',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding."  * WARNING : this object seems to be used so deletion may fail.\n";
        }

        if( $context->isAPI )
            $object->owner->API_remove($object);
        else
            $object->owner->remove($object);
    },
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'decommission',
    'GlobalInitFunction' => function(AddressCallContext $context)
    {
        $context->objecttodelete = Array();
    },
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $context->arguments['file'] !== "false" )
        {
            if( !isset($context->cachedList) )
            {
                $text = file_get_contents( $context->arguments['file'] );

                if( $text === false )
                    derr("cannot open file '{$context->arguments['file']}");

                $lines = explode("\n", $text);
                foreach( $lines as  $line)
                {
                    $line = trim($line);
                    if(strlen($line) == 0)
                        continue;
                    $list[$line] = true;
                }

                $context->cachedList = &$list;
            }
            else
                $list = &$context->cachedList;
        }
        else
            $list[] = $object->name();

        foreach( $list as $key => $item )
        {
            if( $object->name() == $key )
            {
                if( $object->countReferences() != 0 )
                {
                    print "delete all references: \n";
                    print $object->display_references();

                    if( $context->isAPI )
                        $object->API_removeWhereIamUsed( true );
                    else
                        $object->removeWhereIamUsed( true );
                }
                $context->objecttodelete[] = $object;
            }
        }
    },
    'GlobalFinishFunction' => function(AddressCallContext $context)
    {
        print "\n\n".PH::boldText( "DELETE ADDRESS OBJECTS:" )."\n";
        foreach( $context->objecttodelete as $object )
        {
            //error handling enabled because of address object reference settings in :
            //- interfaces: ethernet/vlan/loopback/tunnel
            //- IKE gateway
            // is not implemented yet
            PH::enableExceptionSupport();
            try
            {

                if( $context->isAPI )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
                print "finally delete address object: " .$object->name()."\n";

            } catch(Exception $e)
            {
                PH::disableExceptionSupport();
                print "\n\n " . PH::boldText("  ***** an error occured : ") . $e->getMessage() . "\n\n";

                print PH::boldText( "address object: ". $object->name() . " can not be removed. Check error message above.\n");

                return;
            }
        }
    },
    'args' => Array(
        'file' => Array( 'type' => 'string', 'default' => 'false' ),
    ),
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'replace-IP-by-MT-like-Object',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( !$object->isTmpAddr() )
        {
            echo $context->padding."     *  SKIPPED because object is not temporary or not an IP address/netmask\n";
            return;
        }

        $rangeDetected = false;

        if( !$object->nameIsValidRuleIPEntry() )
        {
            echo $context->padding . "     *  SKIPPED because object is not an IP address/netmask or range\n";
            return;
        }

        $objectRefs = $object->getReferences();
        $clearForAction = true;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'NatRule' )
            {
                $clearForAction = false;
                echo $context->padding."     *  SKIPPED because its used in unsupported class $class\n";
                return;
            }
        }

        $pan = PH::findRootObjectOrDie($object->owner);

        if( strpos($object->name(), '-') === FALSE )
        {
            $explode = explode('/',$object->name());

            if( count($explode) > 1 )
            {
                $name = $explode[0];
                $mask = $explode[1];
            }
            else
            {
                $name = $object->name();
                $mask = 32;
            }

            if( $mask > 32 || $mask < 0 )
            {
                echo $context->padding."    * SKIPPED because of invalid mask detected : '$mask'\n";
                return;
            }

            if( filter_var($name, FILTER_VALIDATE_IP) === FALSE )
            {
                echo $context->padding."    * SKIPPED because of invalid IP detected : '$name'\n";
                return;
            }

            if( $mask == 32 )
            {
                $newName = 'H-'.$name;
            }
            else
            {
                $newName = 'N-'.$name.'-'.$mask;
            }
        }
        else
        {
            $rangeDetected = true;
            $explode= explode('-', $object->name());
            $newName = "R-".$explode[0].'-'.$explode[1];
        }

        echo $context->padding."    * new object name will be $newName\n";

        $objToReplace = $object->owner->find($newName);
        if( $objToReplace === null )
        {
            if( $context->isAPI )
            {
                if( $rangeDetected)
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-range', $explode[0].'-'.$explode[1] );
                else
                    $objToReplace = $object->owner->API_newAddress($newName, 'ip-netmask', $name.'/'.$mask);
            }
            else
            {
                if( $rangeDetected)
                    $objToReplace = $object->owner->newAddress($newName, 'ip-range', $explode[0].'-'.$explode[1] );
                else
                    $objToReplace = $object->owner->newAddress($newName, 'ip-netmask', $name.'/'.$mask);
            }
        }
        else
        {
            $objMap = IP4Map::mapFromText($name.'/'.$mask);
            if( !$objMap->equals($objToReplace->getIP4Mapping()) )
            {
                echo "    * SKIPPED because an object with same name exists but has different value\n";
                return;
            }
        }


        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);

                if( $class == 'AddressRuleContainer' )
                {
                    /** @var AddressRuleContainer $objectRef */
                    echo $context->padding."     - replacing in {$objectRef->toString()}\n";

                    if( $objectRef->owner->isNatRule()
                        && $objectRef->name == 'snathosts'
                        && $objectRef->owner->sourceNatTypeIs_DIPP()
                        && $objectRef->owner->snatinterface !== null )
                    {
                        echo $context->padding."        -  SKIPPED because it's a SNAT with Interface IP address\n";
                        continue;
                    }


                    if( $context->isAPI )
                        $objectRef->API_add($objToReplace);
                    else
                        $objectRef->addObject($objToReplace);

                    if( $context->isAPI )
                        $objectRef->API_remove($object);
                    else
                        $objectRef->remove($object);
                }
                elseif( $class == 'NatRule' )
                {
                    /** @var NatRule $objectRef */
                    echo $context->padding."     - replacing in {$objectRef->toString()}\n";

                    if( $context->isAPI )
                        $objectRef->API_setDNAT($objToReplace, $objectRef->dnatports);
                    else
                        $objectRef->replaceReferencedObject($object, $objToReplace);
                }
                else
                {
                    derr("unsupported class '$class'");
                }

            }
        }
    },
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'removeWhereUsed',
    'MainFunction' => function ( AddressCallContext $context )
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

AddressCallContext::$supportedActions[] = Array(
    'name' => 'addObjectWhereUsed',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;
        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        if( $context->isAPI )
            $object->API_addObjectWhereIamUsed($foundObject, true, $context->padding.'  ', false, $context->arguments['skipNatRules']);
        else
            $object->addObjectWhereIamUsed($foundObject, true, $context->padding.'  ', false, $context->arguments['skipNatRules']);
    },
    'args' => Array( 'objectName' => Array( 'type' => 'string', 'default' => '*nodefault*' ),
        'skipNatRules' => Array( 'type' => 'bool', 'default' => false ) )
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'add-member',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;
        $addressObjectName = $context->arguments['addressobjectname'];

        if( !$object->isGroup() )
        {
            echo $context->padding."     *  SKIPPED because object is not an address group\n";
            return;
        }

        $address0bjectToAdd = $object->owner->find( $addressObjectName );
        if( $address0bjectToAdd === null )
        {
            echo $context->padding . "     *  SKIPPED because address object name: " . $addressObjectName . " not found\n";
            return;
        }

        if( $object->has( $address0bjectToAdd ) )
        {
            echo $context->padding."     *  SKIPPED because address object is already a member of this address group\n";
            return;
        }

        if( $context->isAPI )
            $object->API_addMember( $address0bjectToAdd );
        else
            $object->addMember( $address0bjectToAdd );

        return;

    },
    'args' => Array(
        'addressobjectname' => Array( 'type' => 'string', 'default' => '*nodefault*' )
    )
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'AddToGroup',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;
        $objectlocation = $object->getLocationString();

        $addressGroupName = $context->arguments['addressgroupname'];
        $deviceGroupName = $context->arguments['devicegroupname'];

        if( $object->name() == $addressGroupName)
        {
            echo $context->padding."     *  SKIPPED because address group can not added to itself\n";
            return;
        }

        if( $deviceGroupName == '*nodefault*' || $objectlocation == $deviceGroupName )
            $addressGroupToAdd = $object->owner->find( $addressGroupName );
        else
        {
            if( get_class( $object->owner->owner ) == "DeviceGroup" )
            {
                if( isset( $object->owner->owner->childDeviceGroups(true)[ $objectlocation ] ) )
                {
                    echo $context->padding . "     *  SKIPPED because address object is configured in Child DeviceGroup\n";
                    return;
                }
                if( !isset( $object->owner->owner->parentDeviceGroups()[ $deviceGroupName ] ) )
                {
                    echo $context->padding . "     *  SKIPPED because address object is configured at another child DeviceGroup at same level\n";
                    return;
                }

                $deviceGroupToAdd = $object->owner->owner->childDeviceGroups(true)[ $deviceGroupName ];
            }
            elseif( get_class( $object->owner->owner ) == "PanoramaConf" )
                $deviceGroupToAdd = $object->owner->owner->findDeviceGroup( $deviceGroupName );
            elseif( get_class( $object->owner->owner ) == "PANConf" )
                $deviceGroupToAdd = $object->owner->owner->findVirtualSystem( $deviceGroupName );
            else
                derr( "action is not defined yet for class: ".get_class( $object->owner->owner ) );

            $addressGroupToAdd = $deviceGroupToAdd->addressStore->find( $addressGroupName );
        }

        if( $addressGroupToAdd === null )
        {
            echo $context->padding . "     *  SKIPPED because address group name: " . $addressGroupName . " not found\n";
            return;
        }

        if( $addressGroupToAdd->isDynamic() )
        {
            echo $context->padding . "     *  SKIPPED because address group name: " . $addressGroupName . " is not static.\n";
            return;
        }

        if( $addressGroupToAdd->has( $object ) )
        {
            echo $context->padding."     *  SKIPPED because address object is already a member of this address group\n";
            return;
        }

        if( $context->isAPI )
            $addressGroupToAdd->API_addMember( $object );
        else
            $addressGroupToAdd->addMember( $object );

        return;

    },
    'args' => Array(
        'addressgroupname' => Array( 'type' => 'string', 'default' => '*nodefault*' ),
        'devicegroupname' => Array(
            'type' => 'string',
            'default' => '*nodefault*',
            'help' =>
                "please define a DeviceGroup name for Panorama config or vsys name for Firewall config.\n"
        )
    )
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'replaceWithObject',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;
        $objectRefs = $object->getReferences();

        $foundObject = $object->owner->find($context->arguments['objectName']);

        if( $foundObject === null )
            derr("cannot find an object named '{$context->arguments['objectName']}'");

        /** @var AddressGroup|AddressRuleContainer $objectRef */

        foreach ($objectRefs as $objectRef)
        {
            echo $context->padding." * replacing in {$objectRef->toString()}\n";
            if( $context->isAPI )
                $objectRef->API_replaceReferencedObject($object, $foundObject);
            else
                $objectRef->replaceReferencedObject($object, $foundObject);
        }

    },
    'args' => Array( 'objectName' => Array( 'type' => 'string', 'default' => '*nodefault*' ) ),
);
AddressCallContext::$supportedActions[] = Array(
    'name' => 'tag-Add',
    'section' => 'tag',
    'MainFunction' => function(AddressCallContext $context)
    {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding."     *  SKIPPED because object is temporary\n";
            return;
        }
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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'tag-Add-Force',
    'section' => 'tag',
    'MainFunction' => function(AddressCallContext $context)
    {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding."     *  SKIPPED because object is temporary\n";
            return;
        }

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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'tag-Remove',
    'section' => 'tag',
    'MainFunction' => function(AddressCallContext $context)
    {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding."     *  SKIPPED because object is temporary\n";
            return;
        }

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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'tag-Remove-All',
    'section' => 'tag',
    'MainFunction' => function(AddressCallContext $context)
    {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding."     *  SKIPPED because object is temporary\n";
            return;
        }

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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'tag-Remove-Regex',
    'section' => 'tag',
    'MainFunction' => function(AddressCallContext $context)
    {
        $object = $context->object;
        if( $object->isTmpAddr() )
        {
            echo $context->padding."     *  SKIPPED because object is temporary\n";
            return;
        }
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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'z_BETA_summarize',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            echo $context->padding."    - SKIPPED because object is not a group\n";
            return;
        }
        if( $object->isDynamic() )
        {
            echo $context->padding."    - SKIPPED because group is dynamic\n";
            return;
        }

        /** @var AddressGroup $object */
        $members = $object->expand();
        $mapping = new IP4Map();

        $listOfNotConvertibleObjects = Array();

        foreach($members as $member )
        {
            if( $member->isGroup() )
                derr('this is not supported');
            if( $member->type() == 'fqdn' )
            {
                $listOfNotConvertibleObjects[] = $member;
            }

            $mapping->addMap( $member->getIP4Mapping(), true );
        }
        $mapping->sortAndRecalculate();

        $object->removeAll();
        foreach($listOfNotConvertibleObjects as $obj )
            $object->addMember($obj);

        foreach($mapping->getMapArray() as $entry )
        {
            $objectName = 'R-'.long2ip($entry['start']).'-'.long2ip($entry['start']);
            $newObject = $object->owner->find($objectName);
            if( $newObject === null )
                $newObject = $object->owner->newAddress($objectName, 'ip-range', long2ip($entry['start']).'-'.long2ip($entry['start']));
            $object->addMember($newObject);
        }

        echo $context->padding."  - group had ".count($members)." expanded members vs {$mapping->count()} IP4 entries and ".count($listOfNotConvertibleObjects)." unsupported objects\n";

    },
);


AddressCallContext::$supportedActions[] = Array(
    'name' => 'exportToExcel',
    'MainFunction' => function(AddressCallContext $context)
    {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function(AddressCallContext $context)
    {
        $context->objectList = Array();
    },
    'GlobalFinishFunction' => function(AddressCallContext $context)
    {
        $args = &$context->arguments;
        $filename = $args['filename'];

        $addWhereUsed = false;
        $addUsedInLocation = false;
        $addResolveGroupIPCoverage = false;
        $addNestedMembers = false;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = true;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = true;

        if( isset($optionalFields['ResolveIP']) )
            $addResolveGroupIPCoverage = true;

        if( isset($optionalFields['NestedMembers']) )
            $addNestedMembers= true;

        $headers = '<th>location</th><th>name</th><th>type</th><th>value</th><th>description</th><th>tags</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';
        if( $addResolveGroupIPCoverage )
            $headers .= '<th>ip resolution</th>';
        if( $addNestedMembers )
            $headers .= '<th>nested members</th>';

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

                /** @var Address|AddressGroup $object */
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
                    if( $object->isDynamic() )
                    {
                        $lines .= $encloseFunction('group-dynamic');
                        $lines .= $encloseFunction('');
                    }
                    else
                    {
                        $lines .= $encloseFunction('group-static');
                        $lines .= $encloseFunction($object->members());
                    }
                    $lines .= $encloseFunction($object->description(), false);
                    $lines .= $encloseFunction($object->tags->tags());
                }
                elseif ( $object->isAddress() )
                {
                    if( $object->isTmpAddr() )
                    {
                        $lines .= $encloseFunction('unknown');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                        $lines .= $encloseFunction('');
                    }
                    else
                    {
                        $lines .= $encloseFunction($object->type());
                        $lines .= $encloseFunction($object->value());
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
                if( $addResolveGroupIPCoverage )
                {
                    $mapping = $object->getIP4Mapping();
                    $strMapping = explode( ',',$mapping->dumpToString());

                    foreach( array_keys($mapping->unresolved) as $unresolved )
                        $strMapping[] = $unresolved;

                    $lines .= $encloseFunction($strMapping);
                }
                if( $addNestedMembers )
                {
                    if( $object->isGroup() )
                    {
                        $members = $object->expand(true);
                        $lines .= $encloseFunction($members);
                    }
                    else
                        $lines .= $encloseFunction('');
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


        file_put_contents($filename, $content);
    },
    'args' => Array(    'filename' => Array( 'type' => 'string', 'default' => '*nodefault*' ),
                        'additionalFields' =>
                            Array( 'type' => 'pipeSeparatedList',
                                'subtype' => 'string',
                                'default' => '*NONE*',
                                'choices' => Array('WhereUsed', 'UsedInLocation', 'ResolveIP', 'NestedMembers'),
                                'help' =>
                                    "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n".
                                    "  - NestedMembers: lists all members, even the ones that may be included in nested groups\n".
                                    "  - ResolveIP\n".
                                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n".
                                    "  - WhereUsed : list places where object is used (rules, groups ...)\n"
                            )
    )

);


AddressCallContext::$supportedActions[] = Array(
    'name' => 'replaceByMembersAndDelete',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( !$object->isGroup() )
        {
            echo $context->padding." - SKIPPED : it's not a group\n";
            return;
        }

        if( $object->owner === null )
        {
            echo $context->padding." -  SKIPPED : object was previously removed\n";
            return;
        }

        $objectRefs = $object->getReferences();
        $clearForAction = true;
        foreach( $objectRefs as $objectRef )
        {
            $class = get_class($objectRef);
            if( $class != 'AddressRuleContainer' && $class != 'AddressGroup' )
            {
                $clearForAction = false;
                echo "- SKIPPED : it's used in unsupported class $class\n";
                return;
            }
        }
        if( $clearForAction )
        {
            foreach( $objectRefs as $objectRef )
            {
                $class = get_class($objectRef);
                /** @var AddressRuleContainer|AddressGroup $objectRef */

                if( $objectRef->owner === null )
                {
                    echo $context->padding."  - SKIPPED because object already removed ({$objectRef->toString()})\n";
                    continue;
                }

                echo $context->padding."  - adding members in {$objectRef->toString()}\n";

                if( $class == 'AddressRuleContainer' )
                {
                    /** @var AddressRuleContainer $objectRef */
                    foreach( $object->members() as $objectMember )
                    {
                        if( $context->isAPI )
                            $objectRef->API_add($objectMember);
                        else
                            $objectRef->addObject($objectMember);

                        echo $context->padding."     -> {$objectMember->toString()}\n";
                    }
                    if( $context->isAPI )
                        $objectRef->API_remove($object);
                    else
                        $objectRef->remove($object);
                }
                elseif( $class == 'AddressGroup')
                {
                    /** @var AddressGroup $objectRef */
                    foreach( $object->members() as $objectMember )
                    {
                        if( $context->isAPI )
                            $objectRef->API_addMember($objectMember);
                        else
                            $objectRef->addMember($objectMember);
                        echo $context->padding."     -> {$objectMember->toString()}\n";
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

AddressCallContext::$supportedActions[] = Array(
    'name' => 'name-Rename',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpAddr() )
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
        if( strpos( $newName, '$$value.no-netmask$$' ) !== FALSE )
        {
            if( $object->isType_ipNetmask() )
                $replace = $object->getNetworkValue();
            else
                $replace = $object->value();

            $newName = str_replace( '$$value.no-netmask$$',  $replace, $newName);
        }
        if( strpos( $newName, '$$netmask$$' ) !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                echo $context->padding." *** SKIPPED : 'netmask' alias is not compatible with this type of objects\n";
                return;
            }
            $replace = $object->getNetworkMask();

            $newName = str_replace( '$$netmask$$',  $replace, $newName);
        }
        if( strpos( $newName, '$$netmask.blank32$$' ) !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                echo $context->padding." *** SKIPPED : 'netmask' alias is not compatible with this type of objects\n";
                return;
            }

            $replace = '';
            $netmask = $object->getNetworkMask();
            if( $netmask != 32 )
                $replace = $object->getNetworkMask();

            $newName = str_replace( '$$netmask.blank32$$',  $replace, $newName);
        }
        if( strpos( $newName, '$$reverse-dns$$' ) !== FALSE )
        {
            if( !$object->isType_ipNetmask() )
            {
                echo $context->padding." *** SKIPPED : 'reverse-dns' alias is compatible with ip-netmask type objects\n";
                return;
            }
            if( $object->getNetworkMask() != 32 )
            {
                echo $context->padding." *** SKIPPED : 'reverse-dns' actions only works on /32 addresses\n";
                return;
            }

            $ip = $object->getNetworkValue();
            $reverseDns = gethostbyaddr( $ip );

            if( $ip == $reverseDns )
            {
                echo $context->padding." *** SKIPPED : 'reverse-dns' could not be resolved\n";
                return;
            }

            $newName = str_replace( '$$reverse-dns$$',  $reverseDns, $newName);
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
            "  - \$\$current.name\$\$ : current name of the object\n".
            "  - \$\$netmask\$\$ : netmask\n".
            "  - \$\$netmask.blank32\$\$ : netmask or nothing if 32\n".
            "  - \$\$reverse-dns\$\$ : value truncated of netmask if any\n".
            "  - \$\$value\$\$ : value of the object\n".
            "  - \$\$value.no-netmask\$\$ : value truncated of netmask if any\n")
    ),
    'help' => ''
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'name-addPrefix',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $newName = $context->arguments['prefix'].$object->name();
        echo $context->padding." - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            echo $context->padding." *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName) !== null )
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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'name-addSuffix',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        $newName = $object->name().$context->arguments['suffix'];
        echo $context->padding." - new name will be '{$newName}'\n";
        if( strlen($newName) > 63 )
        {
            echo $context->padding." *** SKIPPED : resulting name is too long\n";
            return;
        }
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $object->owner->find($newName) !== null )
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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'name-removePrefix',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

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

        if( $object->owner->find($newName) !== null )
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
AddressCallContext::$supportedActions[] = Array(
    'name' => 'name-removeSuffix',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

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

        if( $object->owner->find($newName) !== null )
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

AddressCallContext::$supportedActions[] = Array(
    'name' => 'move',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isTmpAddr() )
        {
            echo $context->padding." * SKIPPED this is a temporary object\n";
            return;
        }

        $localLocation = 'shared';

        if( ! $object->owner->owner->isPanorama() && !$object->owner->owner->isFirewall() )
            $localLocation = $object->owner->owner->name();

        $targetLocation = $context->arguments['location'];
        $targetStore = null;

        if( $localLocation == $targetLocation )
        {
            echo $context->padding." * SKIPPED because original and target destinations are the same: $targetLocation\n";
            return;
        }

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $targetLocation == 'shared' )
        {
            $targetStore = $rootObject->addressStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->addressStore;
        }

        if( $localLocation == 'shared' )
        {
            echo $context->padding."   * SKIPPED : moving from SHARED to sub-level is not yet supported\n";
            return;

            /*
            $location1 = PH::findLocationObjectOrDie($object);
            $locations = $location1->childDeviceGroups(true);
            print_r($locations);

            foreach( $object->getReferences() as $ref )
            {
                if( PH::getLocationString($ref) == "shared" )
                {
                    echo $context->padding."   * SKIPPED : moving from SHARED to sub-level is NOT possible because of references\n";
                    return;
                }
            }
            */
        }

        if( $localLocation != 'shared' && $targetLocation != 'shared' )
        {
            if( $context->baseObject->isFirewall() )
            {
                echo $context->padding."   * SKIPPED : moving between VSYS is not supported\n";
                return;
            }

            echo $context->padding."   * SKIPPED : moving between 2 VSYS/DG is not supported yet\n";
            return;
        }

        $conflictObject = $targetStore->find($object->name() ,null, false);
        if( $conflictObject === null )
        {
            if( $object->isGroup() && !$object->isDynamic() )
            {
                foreach($object->members() as $memberObject)
                    if( $targetStore->find($memberObject->name()) === NULL )
                    {
                        echo $context->padding."   * SKIPPED : this group has an object named '{$memberObject->name()} that does not exist in target location '{$targetLocation}'\n";
                        return;
                    }
            }

            echo $context->padding."   * moved, no conflict\n";
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
            echo $context->padding."   * SKIPPED : there is an object with same name. Choose another mode to resolve this conflict\n";
            return;
        }

        echo $context->padding."   - there is a conflict with an object of same name and type. Please use address-merger.php script with argument 'allowmergingwithupperlevel'";
        if( $conflictObject->isGroup() )
            echo "Group\n";
        else
            echo $conflictObject->type()."\n";

        if( $conflictObject->isGroup() && !$object->isGroup() || !$conflictObject->isGroup() && $object->isGroup() )
        {
            echo $context->padding."   * SKIPPED because conflict has mismatching types\n";
            return;
        }

        if( $conflictObject->isTmpAddr() )
        {
            derr("unsupported situation with a temporary object");
            return;
        }

        if( $object->isTmpAddr() )
        {
            echo $context->padding."   * SKIPPED because this object is Tmp\n";
            return;
        }

        if( $object->isGroup() )
        {
            if( $object->equals($conflictObject) )
            {
                echo "    * Removed because target has same content\n";

                $object->replaceMeGlobally($conflictObject);
                if($context->isAPI)
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);

                return;
            }
            else
            {
                $object->displayValueDiff($conflictObject, 9);
                if( $context->arguments['mode'] == 'removeifmatch')
                {
                    echo $context->padding."    * SKIPPED because of mismatching group content\n";
                    return;
                }

                $localMap = $object->getIP4Mapping();
                $targetMap = $conflictObject->getIP4Mapping();

                if( !$localMap->equals($targetMap) )
                {
                    echo $context->padding."    * SKIPPED because of mismatching group content and numerical values\n";
                    return;
                }

                echo $context->padding."    * Removed because it has same numerical value\n";

                $object->replaceMeGlobally($conflictObject);
                if($context->isAPI)
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);

                return;

            }
        }

        if( $object->equals($conflictObject) )
        {
            echo "    * Removed because target has same content\n";
            $object->replaceMeGlobally($conflictObject);

            if($context->isAPI)
                $object->owner->API_remove($object);
            else
                $object->owner->remove($object);
            return;
        }
        elseif( $object->isType_ipNetmask() )
        {
            if( str_replace('/32', '', $conflictObject->value()) == str_replace('/32', '', $object->value()) )
            {
                echo "    * Removed because target has same content\n";
                $object->replaceMeGlobally($conflictObject);

                if($context->isAPI)
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
                return;
            }
        }

        if( $context->arguments['mode'] == 'removeifmatch' )
            return;

        $localMap = $object->getIP4Mapping();
        $targetMap = $conflictObject->getIP4Mapping();

        if( !$localMap->equals($targetMap) )
        {
            echo $context->padding."    * SKIPPED because of mismatching content and numerical values\n";
            return;
        }

        echo "    * Removed because target has same numerical value\n";

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


AddressCallContext::$supportedActions[] = Array(
    'name' => 'showIP4Mapping',
    'MainFunction' => function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isGroup() )
        {
            $resolvMap=$object->getIP4Mapping();
            echo $context->padding."* {$resolvMap->count()} entries\n";
            foreach($resolvMap->getMapArray() as &$resolvRecord)
            {
                echo $context->padding." - ".str_pad(long2ip($resolvRecord['start']), 14)." - ".long2ip($resolvRecord['end'])."\n";
            }
            /*foreach($resolvMap['unresolved'] as &$resolvRecord)
            {
                echo "     * UNRESOLVED: {$resolvRecord->name()}\n";
            }*/

        }
        else
        {
            $type = $object->type();

            if( $type == 'ip-netmask' || $type == 'ip-range' )
            {
                $resolvMap = $object->getIP4Mapping()->getMapArray();
                $resolvMap = reset($resolvMap);
                echo $context->padding." - ".str_pad(long2ip($resolvMap['start']), 14)." - ".long2ip($resolvMap['end'])."\n";
            }
            else echo $context->padding." - UNSUPPORTED \n";
        }
    }
);


AddressCallContext::$supportedActions[] = Array(
    'name' => 'displayReferences',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;
        $object->display_references(7);
    },
);


AddressCallContext::$supportedActions[] = Array(
    'name' => 'display',
    'MainFunction' =>  function ( AddressCallContext $context )
    {
        $object = $context->object;

        if( $object->isGroup() )
        {
            if( $object->isDynamic() )
            {
                echo $context->padding."* " . get_class($object) . " '{$object->name()}' (DYNAMIC)    desc: '{$object->description()}'\n";
            }
            else
            {
                echo $context->padding."* " . get_class($object) . " '{$object->name()}' ({$object->count()} members)   desc: '{$object->description()}'\n";

                foreach ($object->members() as $member)
                {
                    if($member->isAddress())
                        echo "          - {$member->name()}  value: '{$member->value()}'\n";
                    else
                        echo "          - {$member->name()}\n";
                }

            }
        }
        else
        {
            echo $context->padding."* ".get_class($object)." '{$object->name()}'  value: '{$object->value()}'  desc: '{$object->description()}'\n";
        }


        echo "\n";
    },
);

AddressCallContext::$supportedActions[] = Array(
    'name' => 'description-Append',
    'MainFunction' =>  function(AddressCallContext $context)
    {
        $address = $context->object;
        $description = $address->description();

        if( $address->isTmpAddr() )
        {
            echo $context->padding." *** SKIPPED : object is tmp\n";
            return;
        }

        $textToAppend = "";
        if( $description != "" )
            $textToAppend = " ";
        $textToAppend .= $context->rawArguments['text'];

        if( strlen($description) + strlen($textToAppend) > 253 )
        {
            echo $context->padding." *** SKIPPED : resulting description is too long\n";
            return;
        }

        echo $context->padding." - new description will be: '{$description}{$textToAppend}' ... ";

        if( $context->isAPI )
            $address->API_setDescription($description.$textToAppend);
        else
            $address->setDescription($description.$textToAppend);

        echo "OK";
    },
    'args' => Array( 'text' => Array( 'type' => 'string', 'default' => '*nodefault*' ))
);

//starting with 7.0 PAN-OS support max. 2500 members per group, former 500
AddressCallContext::$supportedActions[] = Array(
    'name' => 'split-large-address-groups',
    'MainFunction' => function(AddressCallContext $context)
    {
        $largeGroupsCount = $context->arguments['largeGroupsCount'];
        $splitCount = $largeGroupsCount - 1;

        $group = $context->object;


        if( $group->isGroup() )
        {
            $membersCount = $group->count();

            // if this group has more members than $largeGroupsCount then we must split it
            if( $membersCount > $largeGroupsCount )
            {
                print "     AddressGroup named '" . $group->name() . "' with $membersCount members \n";

                // get member list in $members
                $members = $group->members();

                $i = 0;

                if( isset($newGroup) ) unset($newGroup);

                // loop move every member to a new subgroup
                foreach( $members as $member )
                {
                    // Condition to detect if previous sub-group is full
                    // so we have to create a new one
                    if( $i % $splitCount == 0 )
                    {
                        if( isset($newGroup) )
                        { // now we can rewrite XML
                            $newGroup->rewriteXML();
                        }

                        // create a new sub-group with name 'original--1'
                        if( $context->isAPI )
                            $newGroup = $group->owner->API_newAddressGroup($group->name() . '--' . ($i / $splitCount));
                        else
                            $newGroup = $group->owner->newAddressGroup($group->name() . '--' . ($i / $splitCount));
                        print "      New AddressGroup object created with name: " . $newGroup->name() . "\n";

                        // add this new sub-group to the original one. Don't rewrite XML for performance reasons.
                        if( $context->isAPI )
                            $group->API_addMember($newGroup, FALSE);
                        else
                            $group->addMember($newGroup, FALSE);
                    }

                    // remove current group member from old group, don't rewrite XML yet for performance savings
                    if( $context->isAPI )
                        $group->API_removeMember($member, FALSE);
                    else
                        $group->removeMember($member, FALSE);

                    // we add current group member to new subgroup
                    if( $context->isAPI )
                        $newGroup->API_addMember($member, FALSE);
                    else
                        $newGroup->addMember($member, FALSE);

                    $i++;
                }
                if( isset($newGroup) )
                { // now we can rewrite XML
                    $newGroup->rewriteXML();
                }

                // Now we can rewrite XML
                $group->rewriteXML();

                print "     AddressGroup count after split: " . $group->count() . " \n";

                print "\n";
            }
            else
                print "     * SKIP: ADDRESS GROUP members count is smaller as largeGroupsCount argument is set: ". $largeGroupsCount ." \n";
        }
        else
            print "     * SKIP: address object is not a ADDRESS GROUP. \n";

    },
    'args' => Array( 'largeGroupsCount' => Array( 'type' => 'string', 'default' => '2490' )
    )
);


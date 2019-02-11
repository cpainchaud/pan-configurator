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


TagCallContext::$supportedActions['delete'] = Array(
    'name' => 'delete',
    'MainFunction' => function ( TagCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0 )
        {
            print $context->padding."  * SKIPPED: this object is used by other objects and cannot be deleted (use deleteForce to try anyway)\n";
            return;
        }
        if( $context->isAPI )
            $object->owner->API_removeTag($object);
        else
            $object->owner->removeTag($object);
    },
);

TagCallContext::$supportedActions['deleteforce'] = Array(
    'name' => 'deleteForce',
    'MainFunction' => function ( TagCallContext $context )
    {
        $object = $context->object;

        if( $object->countReferences() != 0 )
            print $context->padding."  * WARNING : this object seems to be used so deletion may fail.\n";
        if( $context->isAPI )
            $object->owner->API_removeTag($object);
        else
            $object->owner->removeTag($object);
    },
);


TagCallContext::$supportedActions['name-addprefix'] = Array(
    'name' => 'name-addPrefix',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;
        $newName = $context->arguments['prefix'].$object->name();

        if( $object->isTmp() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding." - new name will be '{$newName}'\n";
        if( strlen($newName) > 127 )
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
TagCallContext::$supportedActions['name-addsuffix'] = Array(
    'name' => 'name-addSuffix',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;
        $newName = $object->name().$context->arguments['suffix'];

        if( $object->isTmp() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding." - new name will be '{$newName}'\n";
        if( strlen($newName) > 127 )
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
TagCallContext::$supportedActions['name-removeprefix'] = Array(
    'name' => 'name-removePrefix',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;
        $prefix = $context->arguments['prefix'];

        if( $object->isTmp() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

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
TagCallContext::$supportedActions['name-removesuffix'] = Array(
    'name' => 'name-removeSuffix',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;
        $suffix = $context->arguments['suffix'];
        $suffixStartIndex = strlen($object->name()) - strlen($suffix);

        if( $object->isTmp() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

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
TagCallContext::$supportedActions['name-touppercase'] = Array(
    'name' => 'name-toUpperCase',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtoupper($object->name(), 'UTF8' );

        if( $object->isTmp() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding." - new name will be '{$newName}'\n";
        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            print " *** SKIPPED : object is already uppercase\n";
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, false) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, true) !== null   )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            #use existing uppercase TAG and replace old lowercase where used with this existing uppercase TAG
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);
TagCallContext::$supportedActions['name-tolowercase'] = Array(
    'name' => 'name-toLowerCase',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower( $object->name(), 'UTF8' );

        if( $object->isTmp() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding." - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            print " *** SKIPPED : object is already lowercase\n";
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, false) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, true) !== null   )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            #use existing lowercase TAG and replace old uppercase where used with this
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);
TagCallContext::$supportedActions['name-toucwords'] = Array(
    'name' => 'name-toUCWords',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;
        #$newName = $context->arguments['prefix'].$object->name();
        $newName = mb_strtolower( $object->name(), 'UTF8' );
        $newName = ucwords( $newName );

        if( $object->isTmp() )
        {
            echo $context->padding." *** SKIPPED : not applicable to TMP objects\n";
            return;
        }

        print $context->padding." - new name will be '{$newName}'\n";

        $rootObject = PH::findRootObjectOrDie($object->owner->owner);

        if( $newName === $object->name() )
        {
            print " *** SKIPPED : object is already UCword\n";
            return;
        }

        if( $rootObject->isPanorama() && $object->owner->find($newName, null, false) !== null ||
            $rootObject->isFirewall() && $object->owner->find($newName, null, true) !== null   )
        {
            print " *** SKIPPED : an object with same name already exists\n";
            #use existing lowercase TAG and replace old uppercase where used with this
            return;
        }
        if( $context->isAPI )
            $object->API_setName($newName);
        else

            $object->setName($newName);
    }
);

TagCallContext::$supportedActions['displayreferences'] = Array(
    'name' => 'displayReferences',
    'MainFunction' => function ( TagCallContext $context )
    {
        $object = $context->object;

        $object->display_references(7);
    },
);

TagCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( TagCallContext $context )
    {
        $object = $context->object;
        print "     * ".get_class($object)." '{$object->name()}'  color: '{$object->getColor()}'  comments: '{$object->getComments()}' \n";
        print "\n\n";
    },
);
TagCallContext::$supportedActions['color-set'] = Array(
    'name' => 'Color-set',
    'MainFunction' => function ( TagCallContext $context )
    {
        $color = strtolower( $context->arguments['color'] );

        $object = $context->object;

        if( $context->isAPI )
            $object->API_setColor( $color );
        else
            $object->setColor( $color );
    },
    'args' => Array( 'color' => Array( 
        'type' => 'string', 
        'default' => '*nodefault*', 
        'choices' => Array('none', 'red', 'green', 'blue', 'yellow', 'copper', 'orange', 'purple', 'gray', 'light green', 'cyan', 'light gray', 'blue gray', 'lime', 'black', 'gold', 'brown', 'dark green')  )
    ),
);
TagCallContext::$supportedActions['comments-add'] = Array(
    'name' => 'Comments-add',
    'MainFunction' => function ( TagCallContext $context )
    {
        $comments = $context->arguments['comments'];

        $object = $context->object;

        if( $context->isAPI )
            $object->API_addComments( $comments );
        else
            $object->addComments( $comments );

    },
    'args' => Array( 'comments' => Array( 'type' => 'string', 'default' => '*nodefault*'   )
    ),
);
TagCallContext::$supportedActions['comments-delete'] = Array(
    'name' => 'Comments-delete',
    'MainFunction' => function ( TagCallContext $context )
    {
        $object = $context->object;

        if( $context->isAPI )
            $object->API_deleteComments( );
        else
            $object->deleteComments( );

    },
);
TagCallContext::$supportedActions[] = Array(
    'name' => 'move',
    'MainFunction' =>  function ( TagCallContext $context )
    {
        $object = $context->object;

        /*
        if( $object->isTmpAddr() )
        {
            echo $context->padding." * SKIPPED this is a temporary object\n";
            return;
        }
        */

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
            $targetStore = $rootObject->tagStore;
        }
        else
        {
            $findSubSystem = $rootObject->findSubSystemByName($targetLocation);
            if( $findSubSystem === null )
                derr("cannot find VSYS/DG named '$targetLocation'");

            $targetStore = $findSubSystem->tagStore;
        }

        if( $localLocation == 'shared' )
        {
            echo $context->padding."   * SKIPPED : moving from SHARED to sub-level is not yet supported\n";
            return;
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
            echo $context->padding."   * moved, no conflict\n";
            if( $context->isAPI )
            {
                $oldXpath = $object->getXPath();
                $object->owner->removeTag($object);
                $targetStore->addTag($object);
                $object->API_sync();
                $context->connector->sendDeleteRequest($oldXpath);
            }
            else
            {
                $object->owner->removeTag($object);
                $targetStore->addTag($object);
            }
            return;
        }

        if( $context->arguments['mode'] == 'skipifconflict' )
        {
            echo $context->padding."   * SKIPPED : there is an object with same name. Choose another mode to to resolve this conflict\n";
            return;
        }

        echo $context->padding."   - there is a conflict with an object of same name ";


        if( $object->equals($conflictObject) )
        {
            echo "    * Removed because target has same content\n";
            $object->replaceMeGlobally($conflictObject);

            if($context->isAPI)
                $object->owner->API_removeTag($object);
            else
                $object->owner->removeTag($object);
            return;
        }

    },
    'args' => Array( 'location' => Array( 'type' => 'string', 'default' => '*nodefault*' ),
        'mode' => Array( 'type' => 'string', 'default' => 'skipIfConflict', 'choices' => Array( 'skipIfConflict', 'removeIfMatch') )
    ),
);

TagCallContext::$supportedActions[] = Array(
    'name' => 'exportToExcel',
    'MainFunction' => function(TagCallContext $context)
    {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function(TagCallContext $context)
    {
        $context->objectList = Array();
    },
    'GlobalFinishFunction' => function(TagCallContext $context)
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


        $headers = '<th>location</th><th>name</th><th>color</th><th>description</th>';

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

                /** @var Tag $object */
                if ($count % 2 == 1)
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $encloseFunction(PH::getLocationString($object));

                $lines .= $encloseFunction($object->name());

                if ( $object->isTag() )
                {
                    if( $object->isTmp() )
                    {
                        $lines .= $encloseFunction('unknown');
                        $lines .= $encloseFunction('');

                    }
                    else
                    {
                        $lines .= $encloseFunction($object->color);
                        $lines .= $encloseFunction($object->getComments());
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
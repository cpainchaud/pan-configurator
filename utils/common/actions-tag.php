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
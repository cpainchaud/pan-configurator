<?php
/*
 * Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
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
TagCallContext::$supportedActions['setcolor'] = Array(
    'name' => 'setColor',
    'MainFunction' => function ( TagCallContext $context )
    {
        $color = strtolower( $context->arguments['color'] );

        $object = $context->object;

        if( $context->isAPI )
            $object->API_setColor( $color );
        else
            $object->setColor( $color );

    },
    'args' => Array( 'color' => Array( 'type' => 'string', 'default' => '*nodefault*', 'choices' => array_flip( Tag::$TagColors )  )
    ),
);

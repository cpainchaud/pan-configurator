<?php

// <editor-fold desc=" ***** Address filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['address']['refcount']['operators']['>,<,=,!'] = Array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.unused'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->countReferences() == 0;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.unused.recursive'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        $f = function($ref) use (&$f)
        {
            /** @var Address|AddressGroup $ref */
            if($ref->countReferences() == 0 )
                return true;

            $groups = $ref->findReferencesWithClass('AddressGroup');

            if( count($groups) != $ref->countReferences() )
                return false;

            if( count($groups) == 0 )
                return true;

            foreach( $groups as $group )
            {
                /** @var AddressGroup $group */
                if( $f($group) == false )
                    return false;
            }

            return true;
        };

        return $f($object);

    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.group'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->isGroup() == true;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.tmp'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->isTmpAddr() == true;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-range'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        if( !$context->object->isGroup() )
            return $context->object->isType_ipRange() == true;

        return false;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-netmask'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        if( !$context->object->isGroup() )
            return $context->object->isType_ipNetmask() == true;

        return false;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.fqdn'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        if( !$context->object->isGroup() )
            return $context->object->isType_FQDN() == true;
        else
            return false;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['overrides.upper.level'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $location = PH::findLocationObjectOrDie($context->object);
        if( $location->isFirewall() || $location->isPanorama() || $location->isVirtualSystem() )
            return false;

        $store = $context->object->owner;

        if( isset($store->parentCentralStore) && $store->parentCentralStore !== null )
        {
            $store = $store->parentCentralStore;
            $find = $store->find($context->object->name());

            return $find !== null;
        }
        else
            return false;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['overriden.at.lower.level'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        $location = PH::findLocationObjectOrDie($object);
        if( $location->isFirewall() || $location->isVirtualSystem() )
            return false;

        if( $location->isPanorama() )
            $locations = $location->deviceGroups;
        else
        {
            $locations = $location->childDeviceGroups(true);
        }

        foreach( $locations as $deviceGroup )
        {
            if( $deviceGroup->addressStore->find($object->name(), null, false) !== null )
                return true;
        }

        return false;
    },
    'arg' => false,
    'ci' => Array(
        'fString' => '(%PROP%)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.member.of'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $addressGroup = $context->object->owner->find( $context->value );

        if( $addressGroup === null )
            return false;

        if( $addressGroup->has( $context->object ) )
            return true;

        return false;

    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['object']['operators']['is.recursive.member.of'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $addressGroup = $context->object->owner->find( $context->value );

        if( $addressGroup === null )
            return false;

        if( !$context->object->isGroup() )
        {
            if( $addressGroup->hasObjectRecursive( $context->object ) )
                return true;
        }

        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% grp-in-grp-test-1)',
        'input' => 'input/panorama-8.0-merger.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['eq'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% new test 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['eq.nocase'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% new test 2)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['contains'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return strpos($context->object->name(), $context->value) !== false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% -)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['regex'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%')
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        if( strpos( $value, '$$value$$' ) !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() )
                $replace = str_replace(Array('.', '/'), Array('\.', '\/'), $object->value() );

            $value = str_replace( '$$value$$', $replace, $value);

        }
        if( strpos( $value, '$$value.no-netmask$$' ) !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && $object->isType_ipNetmask() )
                $replace = str_replace('.', '\.', $object->getNetworkValue() );

            $value = str_replace( '$$value.no-netmask$$',  $replace, $value);
        }
        if( strpos( $value, '$$netmask$$' ) !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && $object->isType_ipNetmask() )
                $replace = $object->getNetworkMask();

            $value = str_replace( '$$netmask$$',  $replace, $value);
        }
        if( strpos( $value, '$$netmask.blank32$$' ) !== FALSE )
        {
            $replace = '%%%INVALID\.FOR\.THIS\.TYPE\.OF\.OBJECT%%%';
            if( !$object->isGroup() && $object->isType_ipNetmask() )
            {
                $netmask = $object->getNetworkMask();
                if( $netmask != 32 )
                    $replace = $object->getNetworkMask();
            }

            $value = str_replace( '$$netmask.blank32$$',  $replace, $value);
        }

        if( strlen($value) == 0 )
            return false;
        if( strpos($value, '//') !== FALSE )
            return false;

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return true;

        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% /n-/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['name']['operators']['is.in.file'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( !isset($context->cachedList) )
        {
            $text = file_get_contents($context->value);

            if( $text === false )
                derr("cannot open file '{$context->value}");

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

        return isset($list[$object->name()]);
    },
    'arg' => true
);
RQuery::$defaultFilters['address']['netmask']['operators']['>,<,=,!'] = Array(
    'eval' => '!$object->isGroup() && $object->isType_ipNetmask() && $object->getNetworkMask() !operator! !value!',
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['members.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->isGroup() && \$object->count() !operator! !value!",
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->tags->hasTag($context->value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');",
    'ci' => Array(
        'fString' => '(%PROP% grp.shared-group1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has.nocase'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->tags->hasTag($context->value, false) === true;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% test)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['tag']['operators']['has.regex'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        foreach($context->object->tags->tags() as $tag )
        {
            $matching = preg_match( $context->value, $tag->name() );
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return true;
        }

        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% /grp/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['is'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $owner = $context->object->owner->owner;
        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return true;
            if( $owner->isFirewall() )
                return true;
            return false;
        }
        if( strtolower($context->value) == strtolower($owner->name()) )
            return true;

        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% shared)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['location']['operators']['regex'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $name = $context->object->getLocationString();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return true;
        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% /shared/)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocation']['operators']['is'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;
        $owner = $context->object->owner->owner;

        $reflocation_array = $object->getReferencesLocation();


        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return true;
            if( $owner->isFirewall() )
                return true;
            return false;
        }

        foreach( $reflocation_array as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                return true;
        }


        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reflocation']['operators']['is.only'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $owner = $context->object->owner->owner;
        $reflocations = $context->object->getReferencesLocation();

        if( strtolower($context->value) == 'shared' )
        {
            if( $owner->isPanorama() )
                return true;
            if( $owner->isFirewall() )
                return true;
            return false;
        }

        $return = false;
        foreach( $reflocations as $reflocation )
        {
            if( strtolower($reflocation) == strtolower($context->value) )
                $return = true;
        }

        if( count( $reflocations ) == 1 && $return )
            return true;
        else
            return false;

    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% shared )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['refstore']['operators']['is'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesStoreValidation( $value );

        $refstore = $context->object->getReferencesStore();

        if( array_key_exists( $value, $refstore ) )
            return true;

        return false;

    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% rulestore )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['reftype']['operators']['is'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $value = $context->value;
        $value = strtolower($value);

        $context->object->ReferencesTypeValidation( $value );

        $reftype = $context->object->getReferencesType();

        if( array_key_exists( $value, $reftype ) )
            return true;

        return false;

    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% securityrule )',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['string.eq'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isGroup() )
            return null;

        if( $object->isAddress() )
        {
            if( $object->type() == 'ip-range' || $object->type() == 'ip-netmask' )
            {
                if( $object->value() == $context->value )
                    return true;
            }
        }
        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.match.exact'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        $values = explode(',', $context->value);


        if( !isset($context->cachedValueMapping) )
        {
            $mapping = new IP4Map();

            $count = 0;
            foreach( $values as $net )
            {
                $net = trim($net);
                if( strlen($net) < 1 )
                    derr("empty network/IP name provided for argument #$count");
                $mapping->addMap(IP4Map::mapFromText($net));
                $count++;
            }
            $context->cachedValueMapping = $mapping;
        }
        else
            $mapping = $context->cachedValueMapping;

        return $object->getIP4Mapping()->equals($mapping);
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.included-in'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isAddress() && $object->type() == 'fqdn' )
            return null;

        if( $object->isGroup() && $object->count() < 1 )
            return null;

        $values = explode(',', $context->value);
        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $object->getIP4Mapping()->includedInOtherMap($mapping) == 1;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isAddress() && $object->type() == 'fqdn' )
            return null;

        if( $object->isGroup() && $object->count() < 1 )
            return null;

        $values = explode(',', $context->value);
        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $mapping->includedInOtherMap($object->getIP4Mapping()) == 1;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full-or-partial'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isAddress() && $object->type() == 'fqdn' )
            return null;

        if( $object->isGroup() && $object->count() < 1 )
            return null;

        $values = explode(',', $context->value);
        $mapping = new IP4Map();

        $count = 0;
        foreach( $values as $net )
        {
            $net = trim($net);
            if( strlen($net) < 1 )
                derr("empty network/IP name provided for argument #$count");
            $mapping->addMap(IP4Map::mapFromText($net));
            $count++;
        }

        return $mapping->includedInOtherMap($object->getIP4Mapping()) != 0;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% 1.1.1.1)',
        'input' => 'input/panorama-8.0.xml'
    )
);
RQuery::$defaultFilters['address']['description']['operators']['regex'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;
        $value = $context->value;

        if( strlen($value) > 0 && $value[0] == '%')
        {
            $value = substr($value, 1);
            if( !isset($context->nestedQueries[$value]) )
                derr("regular expression filter makes reference to unknown string alias '{$value}'");

            $value = $context->nestedQueries[$value];
        }

        $matching = preg_match($value, $object->description());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return true;
        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% /test/)',
        'input' => 'input/panorama-8.0.xml'
    )
);

// </editor-fold>
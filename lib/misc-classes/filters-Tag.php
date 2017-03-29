<?php

// <editor-fold desc=" ***** Tag filters *****" defaultstate="collapsed" >
RQuery::$defaultFilters['tag']['refcount']['operators']['>,<,=,!'] = Array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => true
);
RQuery::$defaultFilters['tag']['object']['operators']['is.unused'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        return $context->object->countReferences() == 0;
    },
    'arg' => false
);
RQuery::$defaultFilters['tag']['name']['operators']['is.in.file'] = Array(
    'Function' => function(TagRQueryContext $context )
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
RQuery::$defaultFilters['tag']['object']['operators']['is.tmp'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        return $context->object->isTmp();
    },
    'arg' => false
);
RQuery::$defaultFilters['tag']['name']['operators']['eq'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['tag']['name']['operators']['eq.nocase'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => true
);
RQuery::$defaultFilters['tag']['name']['operators']['contains'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        return strpos($context->object->name(), $context->value) !== false;
    },
    'arg' => true
);
RQuery::$defaultFilters['tag']['name']['operators']['regex'] = Array(
    'Function' => function(TagRQueryContext $context )
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

        $matching = preg_match($value, $object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$value}'");
        if( $matching === 1 )
            return true;
        return false;
    },
    'arg' => true
);
RQuery::$defaultFilters['tag']['location']['operators']['is'] = Array(
    'Function' => function(TagRQueryContext $context )
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
    'arg' => true
);
RQuery::$defaultFilters['tag']['location']['operators']['regex'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        $name = $context->object->getLocationString();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return true;
        return false;
    },
    'arg' => true
);
RQuery::$defaultFilters['tag']['color']['operators']['eq'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        return $context->object->getColor() == strtolower( $context->value );
    },
    'arg' => true
);
RQuery::$defaultFilters['tag']['comments']['operators']['regex'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        $name = $context->object->getComments();
        $matching = preg_match($context->value, $name);
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return true;
        return false;
    },
    'arg' => true
);

RQuery::$defaultFilters['tag']['comments']['operators']['is.empty'] = Array(
    'Function' => function(TagRQueryContext $context )
    {
        $desc = $context->object->getComments();

        if( $desc === null || strlen($desc) == 0 )
            return true;

        return false;
    },
    'arg' => false,
);
// </editor-fold>
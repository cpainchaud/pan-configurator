<?php

// <editor-fold desc=" ***** Application filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['app']['name']['operators']['eq'] = Array(
    'Function' => function(ApplicationRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% ftp)',
        'input' => 'input/panorama-8.0.xml'
    )
);

RQuery::$defaultFilters['app']['characteristic']['operators']['has'] = Array(
    'Function' => function(ApplicationRQueryContext $context )
    {
        $app = $context->object;

        if( $app->isContainer() )
            return null;

        $sanitizedValue = strtolower($context->value);
        if( $app->_characteristics[$sanitizedValue] === true )
                return true;

        return false;
    },
    'arg' => true,
    'ci' => Array(
        'fString' => '(%PROP% evasive) ',
        'input' => 'input/panorama-8.0.xml'
    )
);


// </editor-fold>
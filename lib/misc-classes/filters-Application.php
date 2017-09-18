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


// </editor-fold>
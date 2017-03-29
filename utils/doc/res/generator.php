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

echo "\n***********************************************\n";
echo   "************ DOC GENERATOR  **************\n\n";

require_once("../../../lib/panconfigurator.php");
require_once("../../common/actions.php");

$dataFile = __DIR__.'/data.js';

function &generateActionJSON(&$actions)
{

    $result = Array();
    foreach($actions as $action)
    {
        $record = Array( 'name' => $action['name'],'help' => null, 'args' => false );

        if( isset($action['help']) )
            $record['help'] = str_replace(  Array("\n"  , ' '),
                Array("<br>", '&nbsp'),
                $action['help']);

        if( isset($action['args']) && $action['args'] !== false )
        {
            $record['args'] = Array();
            foreach($action['args'] as $argName => $arg)
            {
                $tmpArr = $arg;
                if( isset($arg['help']) )
                    $arg['help'] = str_replace( Array("\n"  , ' '),
                        Array("<br>", '&nbsp'),
                        $arg['help']);
                $tmpArr['name'] = $argName;
                $record['args'][] = $tmpArr;
            }
        }

        $result[] = $record;
    }

    return $result;
}
$actionsData = Array();
$actionsData['rule'] = generateActionJSON(RuleCallContext::$supportedActions);
$actionsData['address'] = generateActionJSON(AddressCallContext::$supportedActions);
$actionsData['service'] = generateActionJSON(ServiceCallContext::$supportedActions);
$actionsData['tag'] = generateActionJSON(TagCallContext::$supportedActions);

function &generateFilterJSON($filters)
{
    $result = Array();

    ksort($filters);

    foreach( $filters as $name => $filter)
    {
        $record = Array( 'name' => $name,'help' => null, 'operators' => Array() );
        ksort($filter['operators']);

        foreach( $filter['operators'] as $opName => $opDetails)
        {
            $opRecord = Array('name' => $opName, 'help' => null, 'argument' => null);

            if( isset($opDetails['arg']) && $opDetails['arg'] === true )
                $opRecord['argument'] = '*required*';

            if( isset($opDetails['help']) )
                $opRecord['help'] = $opDetails['help'];

            $record['operators'][] = $opRecord;
        }

        $result[] = $record;
    }

    return $result;
}
$filtersData = Array();
$filtersData['rule'] = generateFilterJSON(RQuery::$defaultFilters['rule']);
$filtersData['address'] = generateFilterJSON(RQuery::$defaultFilters['address']);
$filtersData['service'] = generateFilterJSON(RQuery::$defaultFilters['service']);
$filtersData['tag'] = generateFilterJSON(RQuery::$defaultFilters['tag']);


$data = Array('actions' => &$actionsData, 'filters' => &$filtersData );

$data = 'var data = '.json_encode($data, JSON_PRETTY_PRINT) .';';

file_put_contents($dataFile, $data);

echo "\nDOC GENERATED !!!\n\n";
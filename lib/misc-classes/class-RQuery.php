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

class RQuery
{
    /**
     * @var null|string
     */
    public $expression = null;

    /**
     * @var RQuery[]
     */
    public $subQueries = Array();

    /**
     * @var string[]
     */
    public $subQueriesOperators = Array();

    static public $defaultFilters = Array();

    static public $commonFilters = Array();

    static public $mathOps = Array( '>' => '>', '<' => '<', '=' => '==', '==' => '==', '!=' => '!=', '<=' => '<=', '>=' => '>=' );

    public $objectType = null;

    /** @var null|string filter argument */
    public $argument = null;


    /** @var null|string[] */
    public $argumentList = null;

    /** @var array pointer to the operator descriptor */
    public $refOperator;

    /** @var string operator of this rquery  */
    public $operator;

    /** @var  string field to which this Rquery applies */
    public $field;


    public $inverted = false;

    public $level = 0;

    public $text = '';


    public function __construct($objectType, $level = 0)
    {
        $this->level = $level;
        $this->padded = str_pad('', ($this->level+1)*2, ' ');

        $objectType = strtolower($objectType);

        $this->objectType = $objectType;

        if( $this->objectType != "rule" && $this->objectType != "address" && $this->objectType != "service" && $this->objectType != "tag"  )
        {
            derr("unsupported object type '$objectType'");
        }

        if($this->objectType == 'service' )
            $this->contextObject = new ServiceRQueryContext($this);
        elseif($this->objectType == 'address' )
            $this->contextObject = new AddressRQueryContext($this);
        elseif($this->objectType == 'rule' )
            $this->contextObject = new RuleRQueryContext($this);
        elseif($this->objectType == 'tag' )
            $this->contextObject = new TagRQueryContext($this);
    }

    /**
     * @param $queryContext Object|string[]
     * @return bool
     */
    public function matchSingleObject($queryContext)
    {
        if( is_array($queryContext) )
        {
            if( !isset($queryContext['object']) )
                derr('no object provided');

            $object = $queryContext['object'];
            $nestedQueries = &$queryContext['nestedQueries'];
        }
        else
        {
            /** @var string[] $nestedQueries */
            $nestedQueries = Array();
            /** @var SecurityRule|Address|AddressGroup|Service|ServiceGroup $object */
            $object = $queryContext;
            $queryContext = Array('object' => $object, 'nestedQueries' => $nestedQueries);
        }

        if( count($this->subQueries) == 0 )
        {
            // print $this->padded."about to eval\n";
            if( isset($this->refOperator['Function'] ) )
            {
                $boolReturn =  $this->contextObject->execute($object, $nestedQueries);
                if( $boolReturn === null )
                    if( $this->level == 0 )
                        return false;
                    else return null;

                if( $this->inverted )
                    return !$boolReturn;
                return $boolReturn;
            }
            else
            {
                if( $this->refOperator['arg'] == true )
                {
                    if( isset($this->refOperator['argObjectFinder']) )
                    {
                        if( is_string($this->refOperator['argObjectFinder']) )
                        {
                            $eval = str_replace('!value!', $this->argument, $this->refOperator['argObjectFinder']);
                            if( eval($eval) === FALSE )
                            {
                                derr("\neval code was : $eval\n");
                            }
                            if( $objectFind === null )
                            {
                                $locationStr = PH::getLocationString($object);
                                derr( "\n\n**ERROR** cannot find object with name '{$this->argument}' in location '{$locationStr}' or its parents. If you didn't write a typo then try a REGEX based filter instead\n\n" );
                            }
                            if( !is_string($this->refOperator['eval']) )
                            {
                                $boolReturn = $this->refOperator['eval']($object, $nestedQueries, $objectFind);
                            }
                            else
                            {
                                $eval = '$boolReturn = (' . str_replace('!value!', '$objectFind', $this->refOperator['eval']) . ');';

                                if( eval($eval) === FALSE )
                                {
                                    derr("\neval code was : $eval\n");
                                }
                            }
                        }
                        else
                        {
                            $objectFind = $this->refOperator['argObjectFinder']($object, $this->argument);
                            if( $objectFind === false )
                                return false;
                            else
                            {
                                if( $objectFind === null )
                                {
                                    $locationStr = PH::getLocationString($object);
                                    derr( "\n\n**ERROR** cannot find object with name '{$this->argument}' in location '{$locationStr}' or its parents. If you didn't write a typo then try a REGEX based filter instead\n\n" );
                                }
                                if( !is_string($this->refOperator['eval']) )
                                {
                                    $boolReturn = $this->refOperator['eval']($object, $nestedQueries, $objectFind);
                                }
                                else
                                {
                                    $eval = '$boolReturn = (' . str_replace('!value!', '$objectFind', $this->refOperator['eval']) . ');';

                                    if( eval($eval) === FALSE )
                                    {
                                        derr("\neval code was : $eval\n");
                                    }
                                }
                            }

                        }

                        if( $boolReturn === null )
                            if( $this->level == 0 )
                                return false;
                            else return null;

                        if( $this->inverted )
                            return !$boolReturn;
                        return $boolReturn;
                    }
                    else
                    {
                        $boolReturn = false;
                        if( !is_string($this->refOperator['eval']) )
                        {
                            if( $this->argumentList !== null )
                                $boolReturn = $this->refOperator['eval']($object, $nestedQueries, $this->argumentList);
                            else
                                $boolReturn = $this->refOperator['eval']($object, $nestedQueries, $this->argument);
                        }
                        else
                        {
                            $eval = '$boolReturn = (' . str_replace('!value!', $this->argument, $this->refOperator['eval']) . ');';

                            if (isset(self::$mathOps[$this->operator]))
                            {
                                $eval = str_replace('!operator!', self::$mathOps[$this->operator], $eval);
                            }

                            if (eval($eval) === FALSE)
                            {
                                derr("\neval code was : $eval\n");
                            }
                        }

                        if( $boolReturn === null )
                            if( $this->level == 0 )
                                return false;
                            else return null;

                        if( $this->inverted )
                            return !$boolReturn;
                        return $boolReturn;
                    }
                }
                else
                {
                    $boolReturn = false;
                    if( !is_string($this->refOperator['eval']) )
                    {
                        $boolReturn = $this->refOperator['eval']($object, $nestedQueries, null);
                    }
                    else
                    {
                        $eval = '$boolReturn = (' . $this->refOperator['eval'] . ');';

                        if (eval($eval) === FALSE)
                        {
                            derr("\neval code was : $eval\n");
                        }

                    }
                    if( $boolReturn === null )
                        if( $this->level == 0 )
                            return false;
                        else return null;

                    if( $this->inverted )
                        return !$boolReturn;
                    return $boolReturn;
                }
            }
        }


        $queries = $this->subQueries;
        $operators = $this->subQueriesOperators;

        if( count($queries) == 1 )
        {
            $result = $queries[0]->matchSingleObject($queryContext);

            if( $result === null )
                if( $this->level = 0)
                    return false;
                else
                    return null;

            if( $this->inverted )
                return !$result;
            return $result;
        }

        $results = Array();

        foreach( $queries as $query )
        {
            $results[] = $query->matchSingleObject($queryContext);
        }
        //print_r($results);


        $hasAnd = true;

        // processing AND operators
        while( $hasAnd )
        {
            $hasAnd = false;
            $Rkeys = array_keys($results);
            $Rcount = count($results);
            $Okeys = array_keys($operators);
            $Ocount = count($operators);

            for($i=0; $i<$Ocount; $i++)
            {
                if( $operators[$Okeys[$i]] == 'and' )
                {
                    $hasAnd = true;

                    if( $results[$Rkeys[$i]] === null || $results[$Rkeys[$i+1]] === null )
                        $results[$Rkeys[$i]] = null;
                    else
                        $results[$Rkeys[$i]] = $results[$Rkeys[$i]] && $results[$Rkeys[$i+1]];

                    unset($operators[$Okeys[$i]]);
                    unset($results[$Rkeys[$i+1]]);

                    break;
                }
            }
        }

        // Processing OR conditions
        foreach( $results as $res )
        {
            if( $res === true )
            {
                if( $this->inverted )
                    return false;
                return true;
            }
        }
        foreach( $results as $res )
        {
            if( $res === false )
            {
                if( $this->inverted )
                    return true;
                return false;
            }
        }

        if( $this->level == 0 )
            return false;

        return null;

    }


    /**
     * @param string $text
     * @param string $errorMessage
     * @return bool|int FALSE if an error occured (see $errorMessage content)
     */
    public function parseFromString($text, &$errorMessage)
    {
        $this->text = $text;

        $supportedFilters = &self::$defaultFilters[$this->objectType];

        $len = strlen($text);

        $start = 0;
        $previousClose = 0;
        $end = $len -1;

        $findOpen = strpos( $text, '(', $start);
        $findClose = strpos( $text, ')', $start);

        //print $this->padded."Parsing \"$text\"\n";

        while( $findOpen !== FALSE && ($findClose > $findOpen))
        {

            $newQuery = new RQuery($this->objectType, $this->level + 1);
            $this->subQueries[] = $newQuery;

            $res = $newQuery->parseFromString(substr($text, $findOpen+1), $errorMessage );

            if( $res === false )
                return false;

            if( $findOpen != 0 && $text[$findOpen-1] == '!' )
                $newQuery->inverted = true;

            if( count($this->subQueries) > 1)
            {
                if ($newQuery->inverted)
                    $operator = substr($text, $previousClose + 1, $findOpen - $previousClose - 2);
                else
                    $operator = substr($text, $previousClose + 1, $findOpen - $previousClose - 1);

                $operator = self::extractOperatorFromString($operator, $errorMessage);
                if( $operator === false )
                    return false;

                $this->subQueriesOperators[] = $operator;

                ////print $this->padded."raw operator found: '$operator'\n";
            }


            $previousClose = $findOpen + $res;
            //print $this->padded.'remains to be parsed after subQ extracted: '.substr($text,$previousClose+1)."\n";

            $start = $findOpen + $res +1;
            $findOpen = strpos($text, '(', $start);
            $findClose = strpos($text, ')', $start);
        }

        if( $this->level != 0 )
        {
            $findClose = strpos($text, ')', $previousClose+1 );
            if( $findClose === false )
            {
                $errorMessage = 'cannot find closing )';
                //print $this->padded."test\n";
                return false;
            }
            elseif( count($this->subQueries) == 0  )
            {
                $this->text = substr($text, 0,$findClose);

                if( !$this->extractWordsFromText($this->text, $supportedFilters, $errorMessage) )
                    return false;

                if( isset($this->refOperator['deprecated']) )
                {
                    $msg = PH::boldText("\n* ** WARNING ** * ");
                    $msg .= $this->refOperator['deprecated']."\n\n";
                    fwrite(STDERR, $msg);
                }

                return $findClose+1;
            }
            return $findClose+1;
        }

        // here we are at top level
        if( count($this->subQueries) == 0 )
        {
            //print $this->padded."No subquery found, this is an expression: $text\n";
            $this->text = $text;
            if( !$this->extractWordsFromText($this->text, $supportedFilters, $errorMessage) )
            {
                return false;
            }
        }
        else
        {
            //print $this->padded . "Sub-queries found\n";
            $this->text = $text;
        }

        return 1;
    }

    private function extractWordsFromText($text,&$supportedOperations, &$errorMessage)
    {
        $text = trim($text);

        $pos = strpos($text, ' ');

        if( $pos === false )
            $pos = strlen($text);

        $this->field = strtolower(substr($text, 0, $pos));

        if( strlen($this->field) < 1 || !isset($supportedOperations[$this->field]) )
        {
            $errorMessage = "unsupported field name '".$this->field."' in expression '$text'";
            //derr();
            return false;
        }

        $subtext = substr($text, $pos+1);
        $pos = strpos($subtext, ' ');

        if( $pos === false )
            $pos = strlen($subtext);


        $this->operator = strtolower(substr($subtext, 0, $pos));


        $isMathOp = false;

        if( isset(self::$mathOps[$this->operator]) )
        {
            $isMathOp = true;
        }

        if( strlen($this->field) < 1 ||
              !( isset($supportedOperations[$this->field]['operators'][$this->operator]) ||
                  ($isMathOp && isset($supportedOperations[$this->field]['operators']['>,<,=,!'])) ) )
        {
            $errorMessage = "unsupported operator name '".$this->operator."' in expression '$text'";
            return false;
        }

        if( $isMathOp )
            $this->refOperator = &$supportedOperations[$this->field]['operators']['>,<,=,!'];
        else
            $this->refOperator = &$supportedOperations[$this->field]['operators'][$this->operator];

        $subtext = substr($subtext, $pos+1);

        if( (!isset($this->refOperator['arg']) || $this->refOperator['arg'] === false ) && strlen(trim($subtext)) != 0 )
        {
            $errorMessage = "this field/operator does not support argument in expression '$text'";
            return false;
        }


        if( !isset($this->refOperator['arg']) || $this->refOperator['arg'] === false  )
            return true;


        $subtext = trim($subtext);

        if( strlen($subtext) < 1)
        {
            $errorMessage = "missing arguments in expression '$text'";
            return false;
        }

        $this->argument = $subtext;

        if( isset($this->refOperator['argType']) && $this->refOperator['argType'] == 'commaSeparatedList')
        {
            $this->argumentList = explode(',', $subtext);
            if( count($this->argumentList) == 0 )
            {
                $errorMessage = 'expected a list but got an empty string instead';
                return false;
            }
            elseif( count($this->argumentList) == 1 )
            {
                //
                // if the list is only 1 argument long, may be it's a an alias to a text file

                $this->argumentList[0] = trim($this->argumentList[0]);

                if( strlen($this->argumentList[0]) < 1 )
                {
                    $errorMessage = 'expected a list but got an empty string instead';
                    return false;
                }

                // Yes it's an alias !
                if( $this->argumentList[0][0] == '@' )
                {
                    $fileContent = file_get_contents( substr($this->argumentList[0], 1) );
                    $this->argumentList = explode("\n", $fileContent);
                    foreach( $this->argumentList as $itemIndex => &$listItem )
                    {
                        $listItem = trim($listItem);
                        if( strlen($listItem) < 1 )
                            unset($this->argumentList[$itemIndex]);
                    }
                }
            }
            else
            {
                foreach( $this->argumentList as &$listItem )
                {
                    $listItem = trim($listItem);
                }
            }
        }

        return true;

    }

    static private function extractOperatorFromString($text, &$errorMessage)
    {
        $text = trim($text);

        if( count(explode(' ', $text)) != 1 )
        {
            $errorMessage = "unsupported operator: '$text'. Supported is: or,and,&&,||";
            return false;
        }

        $text = strtolower($text);

        if( $text == 'or' || $text == '||' )
            return 'or';

        if( $text == 'and' || $text == '&&' )
            return 'and';

        $errorMessage = "unsupported operator: '$text'. Supported is: or,and,&&,||";
        return false;

    }


    public function display( $indentLevel = 0)
    {
        if( $indentLevel == 0 )
            print $this->sanitizedString();
        else
            print str_pad($this->sanitizedString(), $indentLevel);
    }

    public function sanitizedString()
    {
        $retString = '';

        if( $this->inverted )
            $retString .= '!';

        if( $this->level != 0 )
            $retString .= '(';

        $loop = 0;

        if( count($this->subQueries) > 0 )
        {
            $first = true;
            foreach ($this->subQueries as $query)
            {
                if( $loop > 0 )
                    $retString .= ' '.$this->subQueriesOperators[$loop-1].' ';

                $retString .= $query->sanitizedString();
                $loop++;
            }
        }
        else
        {
            if( isset($this->argument) )
                $retString .= $this->field.' '.$this->operator.' '.$this->argument;
            else
                $retString .= $this->field.' '.$this->operator;
        }

        if( $this->level != 0 )
            $retString .= ")";

        return $retString;
    }

    public function toString()
    {
        return 'RQuery::'.$this->text;
    }
}

/**
 * Class RQueryContext
 * @ignore
 */
class RQueryContext
{
    public $object;

    public $value;

    public $rQueryObject;

    public $nestedQueries;

    /**
     * @param $object Tag
     * @return bool
     */
    function execute($object, $nestedQueries = null)
    {
        if( $nestedQueries !== null )
            $this->nestedQueries = &$nestedQueries;

        $this->object = $object;

        if( $this->rQueryObject->argumentList !== null )
            $this->value = &$this->rQueryObject->argumentList;
        else
            $this->value = &$this->rQueryObject->argument;

        return $this->rQueryObject->refOperator['Function']($this);
    }

}

/**
 * Class RuleRQueryContext
 * @property Rule|SecurityRule|NatRule|PbfRule|AppOverrideRule|CaptivePortalRule|AuthenticationRule|QoSRule $object
 * @ignore
 */
class RuleRQueryContext extends RQueryContext
{
    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

}

/**
 * Class AddressRQueryContext
 * @property Address|AddressGroup $object
 * @ignore
 */
class AddressRQueryContext extends RQueryContext
{
    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }
}

/**
 * Class ServiceRQueryContext
 * @property Service|ServiceGroup $object
 * @ignore
 */
class ServiceRQueryContext extends RQueryContext
{
    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }
}

/**
 * Class TagRQueryContext
 * @property Tag $object
 * @ignore
 */
class TagRQueryContext extends RQueryContext
{
    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

}

/**
 * Class TagRQueryContext
 * @property App $object
 * @ignore
 */
class ApplicationRQueryContext extends RQueryContext
{
    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

}

require_once 'filters-Rule.php';
require_once 'filters-Address.php';
require_once 'filters-Service.php';
require_once 'filters-Tag.php';
require_once 'filters-Application.php';


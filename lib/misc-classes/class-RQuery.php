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

    static public $mathOps = Array( '>' => '>', '<' => '<', '=' => '==', '==' => '==', '!=' => '!=', '<=' => '<=', '>=' => '>=' );

    public $objectType = null;

    public $argument = null;


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
                                fwrite(STDERR, "\n\n**ERROR** cannot find object with name '{$this->argument}' in location '{$locationStr}' or its parents. If you didn't write a typo then try a REGEX based filter instead\n\n");
                                exit(1);
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
                                    fwrite(STDERR, "\n\n**ERROR** cannot find object with name '{$this->argument}' in location '{$locationStr}' or its parents. If you didn't write a typo then try a REGEX based filter instead\n\n");
                                    exit(1);
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

                        if( $this->inverted )
                            return !$boolReturn;
                        return $boolReturn;
                    }
                    else
                    {
                        if( !is_string($this->refOperator['eval']) )
                        {
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
                        if ($this->inverted)
                            return !$boolReturn;

                        return $boolReturn;

                    }
                }
                else
                {
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
            if( $this->inverted )
                return !$queries[0]->matchSingleObject($queryContext);
            return $queries[0]->matchSingleObject($queryContext);
        }

        $results = Array();

        foreach( $queries as $query )
        {
            $results[] = $query->matchSingleObject($queryContext);
        }
        //print_r($results);


        $hasAnd = true;

        // processing 'and' operators
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
                    $results[$Rkeys[$i]] = $results[$Rkeys[$i]] && $results[$Rkeys[$i+1]];

                    unset($operators[$Okeys[$i]]);
                    unset($results[$Rkeys[$i+1]]);

                    break;
                }
            }
        }

        foreach( $results as $res )
        {
            if( $res == true )
            {
                if( $this->inverted )
                    return false;
                return true;
            }
        }

        if( $this->inverted )
            return true;
        return false;

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

        if( $this->refOperator['arg'] === false && strlen(trim($subtext)) != 0 )
        {
            $errorMessage = "this field/operator does not support argument in expression '$text'";
            return false;
        }


        if( $this->refOperator['arg'] === false )
            return true;


        $subtext = trim($subtext);

        if( strlen($subtext) < 1)
        {
            $errorMessage = "missing arguments in expression '$text'";
            return false;
        }

        $this->argument = $subtext;


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


}

/**
 * Class RuleRQueryContext
 * @ignore
 */
class RuleRQueryContext extends RQueryContext
{
    /** @var  SecurityRule|NatRule|DecryptionRule|AppOverrideRule|PbfRule|CaptivePortalRule */
    public $object;
    public $value;

    public $rQueryObject;

    public $nestedQueries;

    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object SecurityRule|NatRule|DecryptionRule|AppOverrideRule
     * @return bool
     */
    function execute($object, $nestedQueries = null)
    {
        if( $nestedQueries !== null )
            $this->nestedQueries = &$nestedQueries;

        $this->object = $object;
        $this->value = &$this->rQueryObject->argument;

        return $this->rQueryObject->refOperator['Function']($this);
    }

}

/**
 * Class AddressRQueryContext
 * @ignore
 */
class AddressRQueryContext extends RQueryContext
{
    /** @var  Address|AddressGroup */
    public $object;
    public $value;

    public $rQueryObject;

    public $nestedQueries;

    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object Address|AddressGroup
     * @return bool
     */
    function execute($object, $nestedQueries = null)
    {
        if( $nestedQueries !== null )
            $this->nestedQueries = &$nestedQueries;

        $this->object = $object;
        $this->value = &$this->rQueryObject->argument;

        return $this->rQueryObject->refOperator['Function']($this);
    }

}

/**
 * Class ServiceRQueryContext
 * @ignore
 */
class ServiceRQueryContext extends RQueryContext
{
    /** @var  Service|ServiceGroup */
    public $object;
    public $value;

    public $rQueryObject;

    public $nestedQueries;

    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object Service|ServiceGroup
     * @return bool
     */
    function execute($object, $nestedQueries = null)
    {
        if( $nestedQueries !== null )
            $this->nestedQueries = &$nestedQueries;

        $this->object = $object;
        $this->value = &$this->rQueryObject->argument;

        return $this->rQueryObject->refOperator['Function']($this);
    }

}

/**
 * Class ServiceRQueryContext
 * @ignore
 */
class TagRQueryContext extends RQueryContext
{
    /** @var  Tag */
    public $object;
    public $value;

    public $rQueryObject;

    public $nestedQueries;

    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object Tag
     * @return bool
     */
    function execute($object, $nestedQueries = null)
    {
        if( $nestedQueries !== null )
            $this->nestedQueries = &$nestedQueries;

        $this->object = $object;
        $this->value = &$this->rQueryObject->argument;

        return $this->rQueryObject->refOperator['Function']($this);
    }

}

// <editor-fold desc=" ***** Rule filters *****" defaultstate="collapsed" >

//                                              //
//                Zone Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['from']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() && !$object->isZoneBased() )
            return $object->from->hasInterface($value) === true;

        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->from->hasInterface($value) === true;

        return $object->from->hasZone($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"



);
RQuery::$defaultFilters['rule']['from']['operators']['has.only'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() && !$object->isZoneBased() )
            return $object->from->hasInterface($value) === true && $object->from->count() == 1;
        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->from->hasInterface($value) === true && $object->from->count() == 1;

        return $object->from->count() == 1 && $object->from->hasZone($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"
);

RQuery::$defaultFilters['rule']['to']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return false;

        if( $object->isDoSRule() && !$object->isZoneBasedTo() )
            return $object->to->hasInterface($value) === true;

        return $object->to->hasZone($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => function($object, $argument)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return false;

        return $object->to->parentCentralStore->find($argument);
    },
    'help' => 'returns TRUE if field TO is using zone mentionned in argument. Ie: "(to has Untrust)"'
);
RQuery::$defaultFilters['rule']['to']['operators']['has.only'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        if( $object->isPbfRule() )
            return false;

        if( $object->isDoSRule() && !$object->isZoneBasedFrom() )
            return $object->to->hasInterface($value) === true && $object->to->count() == 1;

        return $object->to->count() == 1 && $object->to->hasZone($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->to->parentCentralStore->find('!value!');"
);


RQuery::$defaultFilters['rule']['from']['operators']['has.regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        foreach($context->object->from->getAll() as $zone )
        {
            $matching = preg_match($context->value, $zone->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return true;
        }
        return false;
    },
    'arg' => true,
);
RQuery::$defaultFilters['rule']['to']['operators']['has.regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->isPbfRule() )
            return false;

        foreach($context->object->to->getAll() as $zone )
        {
            $matching = preg_match( $context->value, $zone->name() );
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return true;
        }
        return false;
    },
    'arg' => true,
);

RQuery::$defaultFilters['rule']['from.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->from->count() !operator! !value!",
    'arg' => true
);
RQuery::$defaultFilters['rule']['to.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->to->count() !operator! !value!",
    'arg' => true
);

RQuery::$defaultFilters['rule']['from']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->from->isAny();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['to']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->isPbfRule() )
            return false;

        return $context->object->to->isAny();
    },
    'arg' => false
);

//                                              //
//                NAT Dst/Src Based Actions     //
//                                              //
RQuery::$defaultFilters['rule']['snathost']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        if (!$object->isNatRule()) return false;

        return $object->snathosts->has($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->owner->owner->addressStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['dnathost']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value) {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        if (!$object->isNatRule()) return false;
        if ($object->dnathost === null) return false;

        return $object->dnathost === $value;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->owner->owner->addressStore->find('!value!');"
);

//                                              //
//                SNAT Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['snat']['operators']['is.static'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isNatRule() ) return false;
        if( !$context->object->sourceNatTypeIs_Static() ) return false;

        return true;
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['snat']['operators']['is.dynamic-ip'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isNatRule() ) return false;
        if( !$context->object->sourceNatTypeIs_Dynamic() ) return false;

        return true;
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['snat']['operators']['is.dynamic-ip-and-port'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isNatRule() )
            return false;

        if( !$context->object->sourceNatTypeIs_DIPP() )
            return false;

        return true;
    },
    'arg' => false
);

//                                              //
//                SNAT interface Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['dst-interface']['operators']['is.set'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isNatRule() )
            return false;

        return $context->object->hasDestinationInterface();
    },
    'arg' => false
);

//                                              //
//                Dst/Src Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['src']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->has($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['src']['operators']['has.only'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->count() == 1 && $object->source->has($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        return $object->source->hasObjectRecursive($value, false) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive.regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $members = $context->object->source->membersExpanded(true);

        foreach( $members as $member)
        {
            $matching = preg_match($context->value, $member->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return true;
        }
        return false;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['dst']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule  $object */
        return $object->destination->has($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['dst']['operators']['has.only'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        return $object->destination->count() == 1 && $object->destination->has($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive'] = Array(
    'eval' => '$object->destination->hasObjectRecursive(!value!, false) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive.regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $members = $context->object->destination->membersExpanded(true);

        foreach( $members as $member)
        {
            $matching = preg_match($context->value, $member->name());
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return true;
        }
        return false;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->source->count() == 0;
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->destination->count() == 0;
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['src']['operators']['is.negated'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->isNatRule() )
            return false;

        return $context->object->sourceIsNegated();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.negated'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->isNatRule() )
            return false;
        
        return $context->object->destinationIsNegated();
    },
    'arg' => false
);

RQuery::$defaultFilters['rule']['src']['operators']['included-in.full'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->source->includedInIP4Network($context->value) == 1;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['included-in.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->source->includedInIP4Network($context->value) == 2;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['included-in.full.or.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->source->includedInIP4Network($context->value) > 0;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.full'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->source->includesIP4Network($context->value) == 1;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->source->includesIP4Network($context->value) == 2;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['includes.full.or.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->source->includesIP4Network($context->value) > 0;
    },
    'arg' => true
);

RQuery::$defaultFilters['rule']['dst']['operators']['included-in.full'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->destination->includedInIP4Network($context->value) == 1;
    },
    'arg' => true,
    'argDesc' => 'ie: 192.168.0.0/24 | 192.168.50.10/32 | 192.168.50.10 | 10.0.0.0-10.33.0.0'
);
RQuery::$defaultFilters['rule']['dst']['operators']['included-in.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->destination->includedInIP4Network($context->value) == 2;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['dst']['operators']['included-in.full.or.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->destination->includedInIP4Network($context->value) > 0;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.full'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->destination->includesIP4Network($context->value) == 1;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->destination->includesIP4Network($context->value) == 2;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['dst']['operators']['includes.full.or.partial'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->destination->includesIP4Network($context->value) > 0;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['has.from.query'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->source->count() == 0 )
            return false;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === false )
                derr('nested query execution error : '.$errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->source->all() as $member )
        {
            if( $rQuery->matchSingleObject(Array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return true;
        }

        return false;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.from.query'] = Array(
    'Function' => function(RuleRQueryContext $context )
                {
                    if( $context->object->destination->count() == 0 )
                        return false;

                    if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
                        derr("cannot find nested query called '{$context->value}'");

                    $errorMessage = '';

                    if( !isset($context->cachedSubRQuery) )
                    {
                        $rQuery = new RQuery('address');
                        if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === false )
                            derr('nested query execution error : '.$errorMessage);
                        $context->cachedSubRQuery = $rQuery;
                    }
                    else
                        $rQuery = $context->cachedSubRQuery;

                    foreach( $context->object->destination->all() as $member )
                    {
                        if( $rQuery->matchSingleObject(Array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                            return true;
                    }

                    return false;
                },
    'arg' => true
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive.from.query'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->source->count() == 0 )
            return false;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === false )
                derr('nested query execution error : '.$errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->source->membersExpanded() as $member )
        {
            if( $rQuery->matchSingleObject(Array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return true;
        }

        return false;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive.from.query'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->destination->count() == 0 )
            return false;

        if( $context->value === null || !isset($context->nestedQueries[$context->value]) )
            derr("cannot find nested query called '{$context->value}'");

        $errorMessage = '';

        if( !isset($context->cachedSubRQuery) )
        {
            $rQuery = new RQuery('address');
            if( $rQuery->parseFromString($context->nestedQueries[$context->value], $errorMessage) === false )
                derr('nested query execution error : '.$errorMessage);
            $context->cachedSubRQuery = $rQuery;
        }
        else
            $rQuery = $context->cachedSubRQuery;

        foreach( $context->object->destination->all() as $member )
        {
            if( $rQuery->matchSingleObject(Array('object' => $member, 'nestedQueries' => &$context->nestedQueries)) )
                return true;
        }

        return false;
    },
    'arg' => true
);


//                                                //
//                Tag Based filters              //
//                                              //
RQuery::$defaultFilters['rule']['tag']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        return $object->tags->hasTag($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['tag']['operators']['has.nocase'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->tags->hasTag($context->value, false) === true;
    },
    'arg' => true
    //'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['tag']['operators']['has.regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
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
);
RQuery::$defaultFilters['rule']['tag.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => true
);



//                                              //
//          Application properties              //
//                                              //
RQuery::$defaultFilters['rule']['app']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->apps->isAny();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['app']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        return $object->apps->hasApp($value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->apps->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['app']['operators']['has.nocase'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->apps->hasApp($context->value, false) === true;
    },
    'arg' => true
    //'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);


//                                              //
//          Services properties                 //
//                                              //
RQuery::$defaultFilters['rule']['service']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->services->isAny();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['service']['operators']['is.application-default'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->services->isApplicationDefault();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['service']['operators']['has'] = Array(
    'eval' => function($object, &$nestedQueries, $value)
    {
        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $object */
        return $object->services->has($value) === true;
        },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->services->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['service']['operators']['has.regex'] = Array(
    'eval' => function(RuleRQueryContext $context)
    {
        $rule = $context->object;

        if( $rule->isSecurityRule() )
        {
            foreach( $rule->services->getAll() as $service )
            {
                $matching = preg_match($context->value, $service->name() );
                if( $matching === FALSE )
                    derr("regular expression error on '{$context->value}'");
                if( $matching === 1 )
                    return true;
            }
        }
        elseif( $rule->isNatRule() )
        {
            $matching = preg_match($context->value, $rule->service->name() );
            if( $matching === FALSE )
                derr("regular expression error on '{$context->value}'");
            if( $matching === 1 )
                return true;
        }
        else
            derr("unsupported rule type");

        return false;
    },
    'arg' => true,
);


//                                              //
//                SecurityProfile properties    //
//                                              //
RQuery::$defaultFilters['rule']['secprof']['operators']['not.set'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return false;

        return $context->object->securityProfileIsBlank();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.set'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return false;

        return !$context->object->securityProfileIsBlank();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.profile'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return !$context->object->securityProfileIsBlank() && $context->object->securityProfileType() == "profile";
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.group'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return !$context->object->securityProfileIsBlank() && $context->object->securityProfileType() == "group";
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['secprof']['operators']['group.is'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->securityProfileType() == "group" && $context->object->securityProfileGroup() == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['secprof']['operators']['av-profile.is'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->securityProfileIsBlank() )
            return false;

        if( $context->object->securityProfileType() == "group" )
            return false;

        $profiles = $context->object->securityProfiles();
        if( !isset($profiles['virus']) )
            return false;

        return $profiles['virus'] == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['secprof']['operators']['as-profile.is'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->securityProfileIsBlank() )
            return false;

        if( $context->object->securityProfileType() == "group" )
            return false;

        $profiles = $context->object->securityProfiles();
        if( !isset($profiles['spyware']) )
            return false;

        return $profiles['spyware'] == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['secprof']['operators']['url-profile.is'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->securityProfileIsBlank() )
            return false;

        if( $context->object->securityProfileType() == "group" )
            return false;

        $profiles = $context->object->securityProfiles();
        if( !isset($profiles['url-filtering']) )
            return false;

        return $profiles['url-filtering'] == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['secprof']['operators']['wf-profile.is'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->securityProfileIsBlank() )
            return false;

        if( $context->object->securityProfileType() == "group" )
            return false;

        $profiles = $context->object->securityProfiles();
        if( !isset($profiles['wildfire-analysis']) )
            return false;

        return $profiles['wildfire-analysis'] == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['secprof']['operators']['vuln-profile.is'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->securityProfileIsBlank() )
            return false;

        if( $context->object->securityProfileType() == "group" )
            return false;

        $profiles = $context->object->securityProfiles();
        if( !isset($profiles['vulnerability']) )
            return false;

        return $profiles['vulnerability'] == $context->value;
    },
    'arg' => true
);

//                                              //
//                Other properties              //
//                                              //
RQuery::$defaultFilters['rule']['action']['operators']['is.deny'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->actionIsDeny();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['action']['operators']['is.negative'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return false;
        return $context->object->actionIsNegative();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['action']['operators']['is.allow'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return false;
        return $context->object->actionIsAllow();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['log']['operators']['at.start'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return false;
        return $context->object->logStart();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['log']['operators']['at.end'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return false;
        return $context->object->logEnd();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['logprof']['operators']['is.set'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;

        if( !$rule->isSecurityRule() )
            return false;

        if( $rule->logSetting() === null || $rule->logSetting() == '' )
            return false;

        return true;
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['logprof']['operators']['is'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;
        if( !$rule->isSecurityRule() )
            return false;

        if( $rule->logSetting() === null )
            return false;

        if( $rule->logSetting() == $context->value )
            return true;

        return false;
    },
    'arg' => true,
    'help' => 'return true if Log Forwarding Profile is the one specified in argument'
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.prerule'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->isPreRule();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.postrule'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->isPostRule();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.disabled'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->isDisabled();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.dsri'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return false;
        return $context->object->isDSRIEnabled();
    },
    'arg' => false,
    'help' => 'return TRUE if Disable Server Response Inspection has been enabled'
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.bidir.nat'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isNatRule() )
            return false;

        return $context->object->isBiDirectional();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['has.source.nat'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isNatRule() )
            return false;

        if( $context->object->sourceNatTypeIs_None() )
            return true;

        return false;
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['has.destination.nat'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isNatRule() )
            return false;

        if( $context->object->destinationNatIsEnabled() )
            return false;

        return true;
    },
    'arg' => false
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.universal'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( !$context->object->isSecurityRule() )
            return true;

        if( $context->object->type() != 'universal' )
            return false;

        return true;
    },
    'arg' => false,
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.intrazone'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->owner->owner->version < 61 )
            return false;

        if( !$context->object->isSecurityRule() )
            return false;

        if( $context->object->type() != 'intrazone' )
            return false;

        return true;
    },
    'arg' => false
);

RQuery::$defaultFilters['rule']['rule']['operators']['is.interzone'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        if( $context->object->owner->owner->version < 61 )
            return false;

        if( !$context->object->isSecurityRule() )
            return false;

        if( $context->object->type() != 'interzone' )
            return false;

        return true;
    },
    'arg' => false
);

RQuery::$defaultFilters['rule']['location']['operators']['is'] = Array(
    'Function' => function(RuleRQueryContext $context )
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
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the one specified in argument'
);
RQuery::$defaultFilters['rule']['location']['operators']['regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
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
    'help' => 'returns TRUE if object location (shared/device-group/vsys name) matches the regular expression specified in argument'
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.unused.fast'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $object = $context->object;

        if( !$object->isSecurityRule() && !$object->isNatRule() )
            derr("unsupported filter : rule type " . $object->ruleNature() . " is not supported yet. ".$object->toString());

        $unused_flag = 'unused'.$object->ruleNature();
        $rule_base = $object->ruleNature();

        $sub = $object->owner->owner;
        if( !$sub->isVirtualSystem() && !$sub->isDeviceGroup() )
            derr("this is filter is only supported on non Shared rules ".$object->toString());

        $connector = findConnector($sub);

        if( $connector === null )
            derr("this filter is available only from API enabled PANConf objects");

        if( !isset($sub->apiCache) )
            $sub->apiCache = Array();

        // caching results for speed improvements
        if( !isset($sub->apiCache[$unused_flag]) )
        {
            $sub->apiCache[$unused_flag] = Array();

            $apiCmd = '<show><running><rule-use><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $sub->name() . '</vsys></rule-use></running></show>';

            if( $sub->isVirtualSystem() )
            {
                $apiResult = $connector->sendCmdRequest($apiCmd);

                $rulesXml = DH::findXPath('/result/rules/entry', $apiResult);
                for ($i = 0; $i < $rulesXml->length; $i++)
                {
                    $ruleName = $rulesXml->item($i)->textContent;
                    $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                }
            }
            else
            {
                $devices = $sub->getDevicesInGroup();
                $firstLoop = true;

                foreach($devices as $device)
                {
                    $newConnector = new PanAPIConnector($connector->apihost, $connector->apikey, 'panos-via-panorama', $device['serial']);
                    $newConnector->setShowApiCalls($connector->showApiCalls);
                    $tmpCache = Array();

                    foreach($device['vsyslist'] as $vsys)
                    {
                        $apiCmd = '<show><running><rule-use><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $vsys . '</vsys></rule-use></running></show>';
                        $apiResult = $newConnector->sendCmdRequest($apiCmd);

                        $rulesXml = DH::findXPath('/result/rules/entry', $apiResult);

                        for ($i = 0; $i < $rulesXml->length; $i++)
                        {
                            $ruleName = $rulesXml->item($i)->textContent;
                            if( $firstLoop )
                                $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                            else
                            {
                                $tmpCache[$ruleName] = $ruleName;
                            }
                        }

                        if( !$firstLoop )
                        {
                            foreach( $sub->apiCache[$unused_flag] as $unusedEntry )
                            {
                                if( !isset($tmpCache[$unusedEntry]) )
                                    unset($sub->apiCache[$unused_flag][$unusedEntry]);
                            }
                        }

                        $firstLoop = false;
                    }
                }
            }
        }

        if( isset($sub->apiCache[$unused_flag][$object->name()]) )
            return true;

        return false;
    },
    'arg' => false
);


RQuery::$defaultFilters['rule']['name']['operators']['eq'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {   return $context->object->name() == $context->value;
    },
    'arg' => true,
    'help' => 'returns TRUE if rule name matches the one specified in argument'
);
RQuery::$defaultFilters['rule']['name']['operators']['regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $matching = preg_match($context->value, $context->object->name());
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return true;
        return false;
    },
    'arg' => true,
    'help' => 'returns TRUE if rule name matches the regular expression provided in argument'
);
RQuery::$defaultFilters['rule']['name']['operators']['eq.nocase'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => true
);
RQuery::$defaultFilters['rule']['name']['operators']['contains'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return stripos($context->object->name(), $context->value) !== false;
    },
    'arg' => true
);

RQuery::$defaultFilters['rule']['name']['operators']['is.in.file'] = Array(
    'Function' => function(RuleRQueryContext $context )
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
    'arg' => true,
    'help' => 'returns TRUE if rule name matches one of the names found in text file provided in argument'
);

//                                              //
//                UserID properties             //
//                                              //
RQuery::$defaultFilters['rule']['user']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return false;
        if( $rule->isNatRule() )
            return false;

        return $rule->userID_IsAny();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['user']['operators']['is.known'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return false;
        if( $rule->isNatRule() )
            return false;

        return $rule->userID_IsKnown();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['user']['operators']['is.unknown'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return false;
        if( $rule->isNatRule() )
            return false;

        return $rule->userID_IsUnknown();
    },
    'arg' => false
);
RQuery::$defaultFilters['rule']['user']['operators']['is.prelogon'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $rule = $context->object;
        if( $rule->isDecryptionRule() )
            return false;
        if( $rule->isNatRule() )
            return false;

        return $rule->userID_IsPreLogon();
    },
    'arg' => false
);


RQuery::$defaultFilters['rule']['target']['operators']['is.any'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        return $context->object->target_isAny();
    },
    'arg' => false
);

RQuery::$defaultFilters['rule']['target']['operators']['has'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $vsys = null;

        $ex = explode('/', $context->value);

        if( count($ex) > 2 )
            derr("unsupported syntax for target: '{$context->value}'. Expected something like : 00F120CCC/vsysX");

        if( count($ex) == 1 )
            $serial = $context->value;
        else
        {
            $serial = $ex[0];
            $vsys = $ex[1];
        }

        return $context->object->target_hasDeviceAndVsys($serial, $vsys);
    },
    'arg' => true
);


RQuery::$defaultFilters['rule']['description']['operators']['is.empty'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $desc = $context->object->description();

        if( $desc === null || strlen($desc) == 0 )
            return true;

        return false;
    },
    'arg' => false,
);


RQuery::$defaultFilters['rule']['description']['operators']['regex'] = Array(
    'Function' => function(RuleRQueryContext $context )
    {
        $matching = preg_match($context->value, $context->object->description());
        if( $matching === FALSE )
            derr("regular expression error on '{$context->value}'");
        if( $matching === 1 )
            return true;
        return false;
    },
    'arg' => true,
);

// </editor-fold>


//
//          Address Filters
//

// <editor-fold desc=" ***** Address filters *****" defaultstate="collapsed" >

RQuery::$defaultFilters['address']['refcount']['operators']['>,<,=,!'] = Array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => true
);
RQuery::$defaultFilters['address']['object']['operators']['is.unused'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->countReferences() == 0;
    },
    'arg' => false
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
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['is.group'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->isGroup() == true;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['is.tmp'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->isTmpAddr() == true;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-range'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        if( !$context->object->isGroup() )
            return $context->object->isType_ipRange() == true;

        return false;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['is.ip-netmask'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        if( !$context->object->isGroup() )
            return $context->object->isType_ipNetmask() == true;

        return false;
    },
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['is.fqdn'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        if( !$context->object->isGroup() )
            return $context->object->isType_FQDN() == true;
        else
            return false;
    },
    'arg' => false
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

            return $find === null;
        }
        else
            return false;
    },
    'arg' => false
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
    'arg' => false
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
    'arg' => true
);
RQuery::$defaultFilters['address']['name']['operators']['eq'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['address']['name']['operators']['eq.nocase'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => true
);
RQuery::$defaultFilters['address']['name']['operators']['contains'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return strpos($context->object->name(), $context->value) !== false;
    },
    'arg' => true
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
    'arg' => true
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
    'arg' => true
);
RQuery::$defaultFilters['address']['members.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->isGroup() && \$object->count() !operator! !value!",
    'arg' => true
);
RQuery::$defaultFilters['address']['tag.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->tags->count() !operator! !value!",
    'arg' => true
);
RQuery::$defaultFilters['address']['tag']['operators']['has'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->tags->hasTag($context->value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['address']['tag']['operators']['has.nocase'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        return $context->object->tags->hasTag($context->value, false) === true;
    },
    'arg' => true
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
    'arg' => true
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
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['string.eq'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isGroup() )
            return false;

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
    'arg' => true
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
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.included-in'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isAddress() && $object->type() == 'fqdn' )
            return false;

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
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isAddress() && $object->type() == 'fqdn' )
            return false;

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
    'arg' => true
);
RQuery::$defaultFilters['address']['value']['operators']['ip4.includes-full-or-partial'] = Array(
    'Function' => function(AddressRQueryContext $context )
    {
        $object = $context->object;

        if( $object->isAddress() && $object->type() == 'fqdn' )
            return false;

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
    'arg' => true
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
    'arg' => true
);

// </editor-fold>


//
//          Service Filters
//

// <editor-fold desc=" ***** Service filters *****" defaultstate="collapsed" >
RQuery::$defaultFilters['service']['refcount']['operators']['>,<,=,!'] = Array(
    'eval' => '$object->countReferences() !operator! !value!',
    'arg' => true
);
RQuery::$defaultFilters['service']['object']['operators']['is.unused'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return $context->object->countReferences() == 0;
    },
    'arg' => false
);
RQuery::$defaultFilters['service']['object']['operators']['is.unused.recursive'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        $object = $context->object;

        $f = function($ref) use (&$f)
        {
            /** @var Service|ServiceGroup $ref */
            if($ref->countReferences() == 0 )
                return true;

            $groups = $ref->findReferencesWithClass('ServiceGroup');

            if( count($groups) != $ref->countReferences() )
                return false;

            if( count($groups) == 0 )
                return true;

            foreach( $groups as $group )
            {
                /** @var ServiceGroup $group */
                if( $f($group) == false )
                    return false;
            }

            return true;
        };

        return $f($object);

    },
    'arg' => false
);
RQuery::$defaultFilters['service']['name']['operators']['is.in.file'] = Array(
    'Function' => function(ServiceRQueryContext $context )
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
RQuery::$defaultFilters['service']['object']['operators']['is.group'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return $context->object->isGroup();
    },
    'arg' => false
);
RQuery::$defaultFilters['service']['object']['operators']['is.tcp'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return false;

        if( $object->isGroup() )
            return false;

        return $context->object->isTcp();
    },
    'arg' => false
);
RQuery::$defaultFilters['service']['object']['operators']['is.udp'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        $object = $context->object;
        if( $object->isTmpSrv() )
            return false;

        if( $object->isGroup() )
            return false;

        return $context->object->isUdp();
    },
    'arg' => false
);
RQuery::$defaultFilters['service']['object']['operators']['is.tmp'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return $context->object->isTmpSrv();
    },
    'arg' => false
);
RQuery::$defaultFilters['service']['name']['operators']['eq'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return $context->object->name() == $context->value;
    },
    'arg' => true
);
RQuery::$defaultFilters['service']['name']['operators']['eq.nocase'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return strtolower($context->object->name()) == strtolower($context->value);
    },
    'arg' => true
);
RQuery::$defaultFilters['service']['name']['operators']['contains'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return strpos($context->object->name(), $context->value) !== false;
    },
    'arg' => true
);
RQuery::$defaultFilters['service']['name']['operators']['regex'] = Array(
    'Function' => function(ServiceRQueryContext $context )
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
RQuery::$defaultFilters['service']['members.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->isGroup() && \$object->count() !operator! !value!",
    'arg' => true
);
RQuery::$defaultFilters['service']['tag']['operators']['has'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return $context->object->tags->hasTag($context->value) === true;
    },
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['service']['tag']['operators']['has.nocase'] = Array(
    'Function' => function(ServiceRQueryContext $context )
    {
        return $context->object->tags->hasTag($context->value, false) === true;
    },
    'arg' => true
);
RQuery::$defaultFilters['service']['description']['operators']['regex'] = Array(
    'Function' => function(ServiceRQueryContext $context )
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
    'arg' => true
);
RQuery::$defaultFilters['service']['location']['operators']['is'] = Array(
    'Function' => function(ServiceRQueryContext $context )
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
RQuery::$defaultFilters['service']['location']['operators']['regex'] = Array(
    'Function' => function(ServiceRQueryContext $context )
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
// </editor-fold>


//
//          Tag Filters
//

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




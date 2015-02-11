<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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


    public $inverted = false;

    public $level = 0;


    public function RQuery($objectType, $level = 0)
    {
        $this->level = $level;
        $this->padded = str_pad('', ($this->level+1)*2, ' ');

        $objectType = strtolower($objectType);

        $this->objectType = $objectType;

        if( $this->objectType != "rule" && $this->objectType != "address" && $this->objectType != "service"  )
        {
            derr("unsupported object type '$objectType'");
        }
    }

    /**
     * @param SecurityRule $object
     * @return bool
     */
    public function matchSingleObject($object)
    {
        if( count($this->subQueries) == 0 )
        {
           // print $this->padded."about to eval\n";
            if( $this->refOperator['arg'] == true )
            {
                if( isset($this->refOperator['argObjectFinder']) )
                {
                    $eval = str_replace('!value!', $this->argument, $this->refOperator['argObjectFinder']);
                    if( eval($eval) === FALSE )
                    {
                        derr("\neval code was : $eval\n");
                    }
                    if( $objectFind === null )
                    {
                        fwrite(STDERR, "\n\n**ERROR** cannot find object with name '".$this->argument."'\n\n");
                        exit(1);
                    }
                    $eval = '$boolReturn = ('.str_replace('!value!', '$objectFind', $this->refOperator['eval']).');';
                    if( eval($eval) === FALSE )
                    {
                        derr("\neval code was : $eval\n");
                    }

                    if( $this->inverted )
                        return !$boolReturn;
                    return $boolReturn;
                }
                else
                {
                    $eval = '$boolReturn = ('.str_replace('!value!', $this->argument, $this->refOperator['eval']).');';

                    if( isset(self::$mathOps[$this->operator]))
                    {
                        $eval = str_replace('!operator!', self::$mathOps[$this->operator],$eval);
                    }

                    if( eval($eval) === FALSE )
                    {
                        derr("\neval code was : $eval\n");
                    }
                    if( $this->inverted )
                        return !$boolReturn;
                    return $boolReturn;
                }
            }
            else
            {
                $eval = '$boolReturn = ('.$this->refOperator['eval'].');';

                if( eval($eval) === FALSE )
                {
                    derr("\neval code was : $eval\n");
                }
                if( $this->inverted )
                    return !$boolReturn;
                return $boolReturn;
            }
        }


        $queries = $this->subQueries;
        $operators = $this->subQueriesOperators;

        if( count($queries) == 1 )
        {
            if( $this->inverted )
                return !$queries[0]->matchSingleObject($object);
            return $queries[0]->matchSingleObject($object);
        }

        $results = Array();

        foreach( $queries as $query )
        {
            $results[] = $query->matchSingleObject($object);
        }
        //print_r($results);


        $hasAnd = true;

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
     * @return bool|int
     */
    public function parseFromString($text, &$errorMessage)
    {
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

            $res = $newQuery->parseFromString(substr($text, $findOpen+1), $errorMessage, $supportedFilters );

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
            //$this->text = $text;
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

        if( $this->inverted )
            print '!';

        if( $this->level != 0 )
            print "(";

        $loop = 0;

        if( count($this->subQueries) > 0 )
        {
            $first = true;
            foreach ($this->subQueries as $query)
            {
                if( $loop > 0 )
                    print ' '.$this->subQueriesOperators[$loop-1].' ';
                $query->display();
                $loop++;
            }
        }
        else
        {
            if( isset($this->argument) )
                print $this->field.' '.$this->operator.' '.$this->argument;
            else
                print $this->field.' '.$this->operator;
        }

        if( $this->level != 0 )
            print ")";

    }

    public function toString()
    {
        return 'RQuery::'.$this->text;
    }
}

// <editor-fold desc=" ***** Rule filters *****" defaultstate="collapsed" >

//                                              //
//                Zone Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['from']['operators']['has'] = Array(
    'eval' => '$object->from->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['from']['operators']['has.only'] = Array(
    'eval' => '$object->from->count() == 1 && $object->from->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->from->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['to']['operators']['has'] = Array(
    'eval' => '$object->to->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->to->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['to']['operators']['has.only'] = Array(
    'eval' => '$object->to->count() == 1 && $object->to->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->to->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['from']['operators']['is.any'] = Array(
    'eval' => '$object->from->isAny()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['to']['operators']['is.any'] = Array(
    'eval' => '$object->to->isAny()',
    'arg' => false
);

//                                              //
//                Dst/Src Based Actions            //
//                                              //
RQuery::$defaultFilters['rule']['src']['operators']['has'] = Array(
    'eval' => '$object->source->has(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['src']['operators']['has.only'] = Array(
    'eval' => '$object->source->count() == 1 && $object->source->has(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['has.recursive'] = Array(
    'eval' => '$object->source->hasObjectRecursive(!value!, false) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has'] = Array(
    'eval' => '$object->destination->has(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['rule']['dst']['operators']['has.only'] = Array(
    'eval' => '$object->destination->count() == 1 && $object->destination->has(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['dst']['operators']['has.recursive'] = Array(
    'eval' => '$object->destination->hasObjectRecursive(!value!, false) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['src']['operators']['is.any'] = Array(
    'eval' => '$object->source->count() == 0',
    'arg' => false
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.any'] = Array(
    'eval' => '$object->destination->count() == 0',
    'arg' => false
);
RQuery::$defaultFilters['rule']['src']['operators']['is.negated'] = Array(
    'eval' => '$object->sourceIsNegated()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['dst']['operators']['is.negated'] = Array(
    'eval' => '$object->destinationIsNegated()',
    'arg' => false
);


//                                              //
//                Tag Based filters         //
//                                              //
RQuery::$defaultFilters['rule']['tag']['operators']['has'] = Array(
    'eval' => '$object->tags->hasTag(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['rule']['tag']['operators']['has.nocase'] = Array(
    'eval' => '$object->tags->hasTag("!value!", false) === true',
    'arg' => true
    //'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->tags->parentCentralStore->find('!value!');"
);



//                                              //
//          Application properties              //
//                                              //
RQuery::$defaultFilters['rule']['app']['operators']['is.any'] = Array(
    'eval' => '$object->apps->isAny()',
    'arg' => false
);


//                                              //
//          Services properties                 //
//                                              //
RQuery::$defaultFilters['rule']['services']['operators']['is.any'] = Array(
    'eval' => '$object->services->isAny()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['services']['operators']['is.application-default'] = Array(
    'eval' => '$object->services->isApplicationDefault()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['services']['operators']['has'] = Array(
    'eval' => '$object->services->has(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$object->services->parentCentralStore->find('!value!');"
);


//                                              //
//                SecurityProfile properties    //
//                                              //
RQuery::$defaultFilters['rule']['secprof']['operators']['not.set'] = Array(
    'eval' => '$object->securityProfileType() == "none"',
    'arg' => false
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.profile'] = Array(
    'eval' => '$object->securityProfileType() == "profile"',
    'arg' => false
);
RQuery::$defaultFilters['rule']['secprof']['operators']['is.group'] = Array(
    'eval' => '$object->securityProfileType() == "group"',
    'arg' => false
);
RQuery::$defaultFilters['rule']['secprof']['operators']['group.is'] = Array(
    'eval' => '$object->securityProfileType() == "group" && $object->securityProfileGroup() == "!value!"',
    'arg' => true
);


//                                              //
//                Other properties              //
//                                              //
RQuery::$defaultFilters['rule']['action']['operators']['is.deny'] = Array(
    'eval' => '$object->isDeny()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['action']['operators']['is.allow'] = Array(
    'eval' => '$object->isAllow()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['log']['operators']['at.start'] = Array(
    'eval' => '$object->logStart()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['log']['operators']['at.end'] = Array(
    'eval' => '$object->logEnd()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.prerule'] = Array(
    'eval' => '$object->owner->isPreRulebase()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.postrule'] = Array(
    'eval' => '$object->owner->isPreRulebase()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['rule']['operators']['is.disabled'] = Array(
    'eval' => '$object->isDisabled()',
    'arg' => false
);


RQuery::$defaultFilters['rule']['name']['operators']['eq'] = Array(
    'eval' => "\$object->name() == '!value!'",
    'arg' => true
);
RQuery::$defaultFilters['rule']['name']['operators']['eq.nocase'] = Array(
    'eval' => "strtolower(\$object->name()) == strtolower('!value!')",
    'arg' => true
);
RQuery::$defaultFilters['rule']['name']['operators']['contains'] = Array(
    'eval' => "stripos(\$object->name(), '!value!') !== false",
    'arg' => true
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
    'eval' => '$object->countReferences() == 0',
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['is.group'] = Array(
    'eval' => '$object->isGroup() == 0',
    'arg' => false
);
RQuery::$defaultFilters['address']['object']['operators']['is.tmp'] = Array(
    'eval' => '$object->isTmpAddr() == 0',
    'arg' => false
);
RQuery::$defaultFilters['address']['name']['operators']['eq.nocase'] = Array(
    'eval' => "\$object->name() == '!value!'",
    'arg' => true
);
RQuery::$defaultFilters['address']['name']['operators']['eq'] = Array(
    'eval' => "strtolower(\$object->name()) == strtolower('!value!')",
    'arg' => true
);
RQuery::$defaultFilters['address']['members.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->isGroup() && \$object->count() !operator! !value!",
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
    'eval' => '$object->countReferences() == 0',
    'arg' => false
);
RQuery::$defaultFilters['service']['object']['operators']['is.group'] = Array(
    'eval' => '$object->isGroup() == 0',
    'arg' => false
);
RQuery::$defaultFilters['service']['object']['operators']['is.tmp'] = Array(
    'eval' => '$object->isTmpSrv() == 0',
    'arg' => false
);
RQuery::$defaultFilters['service']['name']['operators']['eq'] = Array(
    'eval' => "\$object->name() == '!value!'",
    'arg' => true
);
RQuery::$defaultFilters['service']['name']['operators']['eq.nocase'] = Array(
    'eval' => "strtolower(\$object->name()) == strtolower('!value!')",
    'arg' => true
);
RQuery::$defaultFilters['service']['members.count']['operators']['>,<,=,!'] = Array(
    'eval' => "\$object->isGroup() && \$object->count() !operator! !value!",
    'arg' => true
);
// </editor-fold>




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


    public $inverted = false;

    public $level = 0;

    public function RQuery($level=0)
    {
        $this->level = $level;
        $this->padded = str_pad('', ($this->level+1)*2, ' ');
    }

    /**
     * @param SecurityRule $rule
     * @return bool
     */
    public function matchSingleRule($rule)
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
                return !$queries[0]->matchSingleRule($rule);
            return $queries[0]->matchSingleRule($rule);
        }

        $results = Array();

        foreach( $queries as $query )
        {
            $results[] = $query->matchSingleRule($rule);
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
     * @param string[] $supportedFilters
     * @return bool|int
     */
    public function parseFromString($text, &$errorMessage, &$supportedFilters = null)
    {
        if( $supportedFilters === null )
            $supportedFilters = &self::$defaultFilters;

        $len = strlen($text);

        $start = 0;
        $previousClose = 0;
        $end = $len -1;

        $findOpen = strpos( $text, '(', $start);
        $findClose = strpos( $text, ')', $start);

        //print $this->padded."Parsing \"$text\"\n";

        while( $findOpen !== FALSE && ($findClose > $findOpen))
        {

            $newQuery = new RQuery($this->level + 1);
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
        if( strlen($this->field) < 1 || !isset($supportedOperations[$this->field]['operators'][$this->operator]) )
        {
            $errorMessage = "unsupported operator name '".$this->operator."' in expression '$text'";
            return false;
        }

        $operator = &$supportedOperations[$this->field]['operators'][$this->operator];
        $this->refOperator = &$supportedOperations[$this->field]['operators'][$this->operator];
        $subtext = substr($subtext, $pos+1);

        if( $operator['arg'] === false && strlen(trim($subtext)) != 0 )
        {
            $errorMessage = "this field/operator does not support argument in expression '$text'";
            return false;
        }


        if( $operator['arg'] === false )
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


//                                              //
//                Zone Based Actions            //
//                                              //
RQuery::$defaultFilters['from']['operators']['has'] = Array(
    'eval' => '$rule->from->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->from->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['from']['operators']['has.only'] = Array(
    'eval' => '$rule->from->count() == 1 && $rule->from->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->from->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['to']['operators']['has'] = Array(
    'eval' => '$rule->to->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->to->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['to']['operators']['has.only'] = Array(
    'eval' => '$rule->to->count() == 1 && $rule->to->hasZone(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->to->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['from']['operators']['is.any'] = Array(
    'eval' => '$rule->from->isAny()',
    'arg' => false
);
RQuery::$defaultFilters['to']['operators']['is.any'] = Array(
    'eval' => '$rule->to->isAny()',
    'arg' => false
);

//                                              //
//                Dst/Src Based Actions            //
//                                              //
RQuery::$defaultFilters['src']['operators']['has'] = Array(
    'eval' => '$rule->source->inStore(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->source->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['src']['operators']['has.only'] = Array(
    'eval' => '$rule->source->count() == 1 && $rule->source->inStore(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['src']['operators']['has.recursive'] = Array(
    'eval' => '$rule->source->hasObjectRecursive(!value!, false) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->source->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['dst']['operators']['has'] = Array(
    'eval' => '$rule->destination->inStore(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->destination->parentCentralStore->find('!value!');"

);
RQuery::$defaultFilters['dst']['operators']['has.only'] = Array(
    'eval' => '$rule->destination->count() == 1 && $rule->destination->inStore(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['dst']['operators']['has.recursive'] = Array(
    'eval' => '$rule->destination->hasObjectRecursive(!value!, false) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->destination->parentCentralStore->find('!value!');"
);
RQuery::$defaultFilters['src']['operators']['is.any'] = Array(
    'eval' => '$rule->source->count() == 0',
    'arg' => false
);
RQuery::$defaultFilters['dst']['operators']['is.any'] = Array(
    'eval' => '$rule->destination->count() == 0',
    'arg' => false
);
RQuery::$defaultFilters['src']['operators']['is.negated'] = Array(
    'eval' => '$rule->sourceIsNegated()',
    'arg' => false
);
RQuery::$defaultFilters['dst']['operators']['is.negated'] = Array(
    'eval' => '$rule->destinationIsNegated()',
    'arg' => false
);


//                                              //
//                Tag Based filters         //
//                                              //
RQuery::$defaultFilters['tag']['operators']['has'] = Array(
    'eval' => '$rule->tags->hasTag(!value!) === true',
    'arg' => true,
    'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->tags->parentCentralStore->find('!value!');"
);
//                                              //
//                Tag Based filters         //
//                                              //
RQuery::$defaultFilters['tag']['operators']['has.nocase'] = Array(
    'eval' => '$rule->tags->hasTag("!value!", false) === true',
    'arg' => true
    //'argObjectFinder' => "\$objectFind=null;\n\$objectFind=\$rule->tags->parentCentralStore->find('!value!');"
);



//                                              //
//          Application properties              //
//                                              //
RQuery::$defaultFilters['app']['operators']['is.any'] = Array(
    'eval' => '$rule->apps->isAny()',
    'arg' => false
);

//                                              //
//          Services properties                 //
//                                              //
RQuery::$defaultFilters['services']['operators']['is.any'] = Array(
    'eval' => '$rule->services->isAny()',
    'arg' => false
);
RQuery::$defaultFilters['services']['operators']['is.application-default'] = Array(
    'eval' => '$rule->services->isApplicationDefault()',
    'arg' => false
);




//                                              //
//                Other properties              //
//                                              //
RQuery::$defaultFilters['action']['operators']['is.deny'] = Array(
    'eval' => '$rule->isDeny()',
    'arg' => false
);
RQuery::$defaultFilters['action']['operators']['is.allow'] = Array(
    'eval' => '$rule->isAllow()',
    'arg' => false
);
RQuery::$defaultFilters['log']['operators']['at.start'] = Array(
    'eval' => '$rule->logStart()',
    'arg' => false
);
RQuery::$defaultFilters['log']['operators']['at.end'] = Array(
    'eval' => '$rule->logEnd()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['operators']['is.prerule'] = Array(
    'eval' => '$rule->owner->isPreRulebase()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['operators']['is.postrule'] = Array(
    'eval' => '$rule->owner->isPreRulebase()',
    'arg' => false
);
RQuery::$defaultFilters['rule']['operators']['has.no.securityprofile'] = Array(
    'eval' => '$rule->securityProfileType() == "none"',
    'arg' => false
);


RQuery::$defaultFilters['name']['operators']['eq'] = Array(
    'eval' => "strtolower(\$rule->name()) == strtolower('!value!')",
    'arg' => true
);
RQuery::$defaultFilters['name']['operators']['contains'] = Array(
    'eval' => "stripos(\$rule->name(), '!value!') !== false",
    'arg' => true
);
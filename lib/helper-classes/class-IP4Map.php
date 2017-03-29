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

class IP4Map
{
    protected $_map = Array();

    public $unresolved = Array();

    public function getMapArray()
    {
        return $this->_map;
    }

    public function &getMapArrayPointer()
    {
        return $this->_map;
    }

    /**
     * @param $text
     * @return IP4Map
     */
    static public function mapFromText($text)
    {
        $map = new IP4Map();

        // if IPv6 detected then we exit with blank mapping
        $ex = explode('/', $text);
        if( filter_var($ex[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE )
        {
            return $map;
        }

        $map->_map[] = cidr::stringToStartEnd($text);
        return $map;
    }

    public function equals(IP4Map $other)
    {
        $ref1 = & $this->_map;
        $ref2 = & $other->_map;

        if( count($ref1) != count($ref2) )
            return false;

        $key1 = array_keys($ref1);
        $key2 = array_keys($ref2);


        for( $i=0; $i<count($key1); $i++)
        {
            if ($ref1[$key1[$i]]['start'] != $ref2[$key2[$i]]['start'] )
                return false;
            if ($ref1[$key1[$i]]['end'] != $ref2[$key2[$i]]['end'] )
                return false;
        }

        return true;
    }


    public function substract( IP4Map $substractedMap )
    {
        $affectedRows = 0;

        foreach( $substractedMap->_map as &$subMap )
        {
            $affectedRows += $this->substractSingleIP4Entry($subMap);

            if( count($this->_map) == 0 )
                break;
        }

        return $affectedRows;
    }

    public function intersection( IP4Map $otherMap )
    {
        $invertedMap = IP4Map::mapFromText('0.0.0.0-255.255.255.255');
        $invertedMap->substract($otherMap);

        $result = clone $otherMap;
        $result->substract($invertedMap);

        return $result;
    }

    public function substractSingleIP4Entry(&$subEntry)
    {
        $affectedRows = 0;

        $arrayCopy = $this->_map;
        $this->_map = Array();

        foreach( $arrayCopy as &$entry )
        {
            if( $subEntry['start'] > $entry['end'] )
            {
                $this->_map[] = &$entry;
                continue;
            }
            elseif( $subEntry['end'] < $entry['start'] )
            {
                $this->_map[] = &$entry;
                continue;
            }
            else if( $subEntry['start'] <= $entry['start'] && $subEntry['end'] >= $entry['end'] )
            {

            }
            elseif( $subEntry['start'] > $entry['start'] )
            {
                if( $subEntry['end'] >= $entry['end'] )
                {
                    $entry['end'] = $subEntry['start'] - 1;
                    $this->_map[] = &$entry;
                }
                else
                {
                    $oldEnd = $entry['end'];
                    $entry['end'] = $subEntry['start'] - 1;
                    $this->_map[] = &$entry;
                    $this->_map[] = Array('start'=> $subEntry['end']+1, 'end' => $oldEnd);
                }
            }
            else
            {
                $entry['start'] = $subEntry['end'] + 1;
                $this->_map[] = &$entry;
            }
            $affectedRows++;
        }

        return $affectedRows;
    }


    public function &mapDiff( IP4Map $other )
    {
        $thisCopy = clone $this;
        $otherCopy = clone $other;

        $diff = Array();

        $thisCopy->substract($otherCopy);
        $diff['plus'] = &$thisCopy->_map;

        $otherCopy->substract($this);
        $diff['minus'] = &$otherCopy->_map;

        return $diff;
    }

    /**
     * @param IP4Map $other
     * @return int 1 if full match, 0 if not match, 2 if partial match
     */
    public function includesOtherMap( IP4Map $other )
    {
        if( $this->count() == 0 )
            return 0;

        $otherCopy = clone $other;

        $affectedRowsOther = $otherCopy->substract($this);

        if( $otherCopy->count() == 0 )
            return 1;

        if( $affectedRowsOther == 0 )
            return 0;

        return 2;
    }

    /**
     * @param IP4Map $other
     * @return int 1 if full match, 0 if not match, 2 if partial match
     */
    public function includedInOtherMap(IP4Map $other)
    {
        if( $other->count() == 0 )
            return 0;

        $thisCopy = clone $this;

        $affectedRowsThis = $thisCopy->substract($other);

        if( $thisCopy->count() == 0 )
            return 1;

        if( $affectedRowsThis == 0 )
            return 0;

        return 2;
    }

    /**
     * @param string $separator
     * @return string
     */
    public function &dumpToString($separator = ',')
    {

        $ret = Array();

        foreach( $this->_map as &$entry )
        {
            if( $entry['start'] == $entry['end'])
                $ret[] = long2ip($entry['start']);
            else
                $ret[] = long2ip($entry['start']).'-'.long2ip($entry['end']);
        }

        $ret = PH::list_to_string($ret, $separator);

        return $ret;
    }


    public function addMap(IP4Map $other, $skipRecalculation=false)
    {
        foreach( $other->_map as $mapEntry)
            $this->_map[] = $mapEntry;

        foreach($other->unresolved as $oName => $object)
        {
            $this->unresolved[$oName] = $object;
        }

        if( !$skipRecalculation )
        {
            $this->sortAndRecalculate();
        }
    }

    /**
     * Usually called after addMap(..., false) for speed enhancements
     */
    public function sortAndRecalculate()
    {
        $newMapping = sortArrayByStartValue($this->_map);

        //print "\nafter sorting\n";
        //foreach($this->_map as $map)
        //    print long2ip($map['start']).'-'.long2ip($map['end'])."\n";

        $mapKeys = array_keys($newMapping);
        $mapCount = count($newMapping);
        for( $i=0; $i<$mapCount; $i++)
        {
            $current = &$newMapping[$mapKeys[$i]];
            //print "\nhandling row ".long2ip($current['start']).'-'.long2ip($current['end'])."\n";
            for( $j=$i+1; $j<$mapCount; $j++)
            {
                //$i++;
                $compare = &$newMapping[$mapKeys[$j]];

                //print "   vs ".long2ip($compare['start']).'-'.long2ip($compare['end'])."\n";

                if( $compare['start'] > $current['end'] + 1 )
                    break;

                if( $current['end'] < $compare['end'] )
                    $current['end'] = $compare['end'];

                //print "     upgraded to ".long2ip($current['start']).'-'.long2ip($current['end'])."\n";
                unset($newMapping[$mapKeys[$j]]);

                $i++;
            }
        }

        $this->_map = &$newMapping;
    }

    public function count()
    {
        return count($this->_map);
    }

    public function getFirstMapEntry()
    {
        if( count($this->_map) == 0 )
            return null;

        return reset($this->_map);
    }

}

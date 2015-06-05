<?php
/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
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

class IP4Map
{
    protected $_map = Array();

    public function getMapArray()
    {
        return $this->_map;
    }

    static public function mapFromText($text)
    {
        $map = new IP4Map();
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


    public function & mapDiff( IP4Map $other )
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

    public function addMap(IP4Map $other, $skipRecalculation=false)
    {
        foreach( $other->_map as $mapEntry)
            $this->_map[] = $mapEntry;

        if( !$skipRecalculation )
        {
            $this->sortAndRecalculate();
        }
    }

    public function sortAndRecalculate()
    {
        $newMapping = sortArrayByStartValue($this->_map);

        $mapKeys = array_keys($newMapping);
        $mapCount = count($newMapping);
        for( $i=0; $i<$mapCount; $i++)
        {
            $current = &$newMapping[$mapKeys[$i]];
            for( $j=$i+1; $j<$mapCount; $j++)
            {
                $compare = &$newMapping[$mapKeys[$j]];

                if( $compare['start'] > $current['end'] + 1 )
                    break;

                $current['end'] = $compare['end'];
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

}

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

class ServiceDstPortMapping
{
    public $tcpPortMap = Array();
    public $udpPortMap = Array();
    /** @var Service[]|ServiceGroup[]  */
    public $unresolved = Array();


    /**
     * @param $text
     * @param bool $tcp
     * @return ServiceDstPortMapping
     */
    static public function mappingFromText($text, $tcp = true)
    {
        $newMapping = new ServiceDstPortMapping();

        $commaExplode = explode(',', $text);

        foreach($commaExplode as &$comma)
        {
            $dashExplode = explode('-',$comma);
            if( count($dashExplode) == 1)
            {
                $port = &$dashExplode[0];
                if( !is_string($port) || strlen($port) == 0)
                    derr("unsupported port number: '$port'");

                if( !is_numeric($port) )
                    derr("port is not an integer: '$port'");

                $port = (int)$port;

                if( $port < 0 || $port > 65535)
                    derr('port value is not within 0-65535');

                if( $tcp )
                    $newMapping->tcpPortMap[] = Array('start' => $port , 'end' => $port);
                else
                    $newMapping->udpPortMap[] = Array('start' => $port , 'end' => $port);
            }
            else
            {
                if( count($dashExplode) > 2 )
                    derr("invalid port range syntax: '$comma'");

                $port = $dashExplode[0];
                if( !is_string($port) || strlen($port) == 0)
                    derr("unsupported port number: '$port'");

                if( !is_numeric($port) )
                    derr("port is not an integer: '$port'");

                $port = (int)$port;

                if( $port < 0 || $port > 65535)
                    derr('port value is not within 0-65535');

                $portStart = $port;

                $port = $dashExplode[1];
                if( !is_string($port) || strlen($port) == 0)
                    derr("unsupported port number: '$port'");

                if( !is_numeric($port) )
                    derr("port is not an integer: '$port'");

                $port = (int)$port;

                if( $port < 0 || $port > 65535)
                    derr('port value is not within 0-65535');

                $portEnd = $port;

                if( $tcp )
                    $newMapping->tcpPortMap[] = Array('start' => $portStart , 'end' => $portEnd);
                else
                    $newMapping->udpPortMap[] = Array('start' => $portStart , 'end' => $portEnd);

            }
        }

        $newMapping->mergeOverlappingMappings();

        return $newMapping;
    }

    private function sortMappings()
    {
        $this->tcpPortMap = & sortArrayByStartValue($this->tcpPortMap);
        $this->udpPortMap = & sortArrayByStartValue($this->udpPortMap);
    }

    public function mergeOverlappingMappings()
    {
        $this->sortMappings();

        $newMapping = & $this->tcpPortMap;

        $mapKeys = array_keys($newMapping);
        $mapCount = count($newMapping);
        for( $i=0; $i<$mapCount; $i++)
        {
            $current = &$newMapping[$mapKeys[$i]];
            //print "     - handling ".long2ip($current['start'])."-".long2ip($current['end'])."\n";
            for( $j=$i+1; $j<$mapCount; $j++)
            {
                $compare = &$newMapping[$mapKeys[$j]];
                //print "       - vs ".long2ip($compare['start'])."-".long2ip($compare['end'])."\n";

                if( $compare['start'] > $current['end'] + 1 )
                    break;

                if( $current['end'] < $compare['end'] )
                    $current['end'] = $compare['end'];

                unset($newMapping[$mapKeys[$j]]);

                $i++;
            }
        }

        $newMapping = & $this->udpPortMap;

        $mapKeys = array_keys($newMapping);
        $mapCount = count($newMapping);
        for( $i=0; $i<$mapCount; $i++)
        {
            $current = &$newMapping[$mapKeys[$i]];
            //print "     - handling ".long2ip($current['start'])."-".long2ip($current['end'])."\n";
            for( $j=$i+1; $j<$mapCount; $j++)
            {
                $compare = &$newMapping[$mapKeys[$j]];
                //print "       - vs ".long2ip($compare['start'])."-".long2ip($compare['end'])."\n";

                if( $compare['start'] > $current['end'] + 1 )
                    break;

                $current['end'] = $compare['end'];

                unset($newMapping[$mapKeys[$j]]);
                $i++;
            }
        }

    }

    public function mergeWithMapping(ServiceDstPortMapping $otherMapping)
    {
        foreach($otherMapping->tcpPortMap as $map)
        {
            $this->tcpPortMap[] = $map;
        }

        foreach($otherMapping->udpPortMap as $map)
        {
            $this->udpPortMap[] = $map;
        }

        $this->mergeOverlappingMappings();
    }

    /**
     * @param $array Service[]|ServiceGroup[]
     */
    public function mergeWithArrayOfServiceObjects($array)
    {
        foreach( $array as $object)
        {
            $this->mergeWithMapping($object->dstPortMapping());
        }
    }

    /**
     * @return string
     */
    public function &tcpMappingToText()
    {
        $returnText = '';

        if( count($this->tcpPortMap) != 0 )
        {
            $mapsText = Array();
            foreach( $this->tcpPortMap as &$map )
            {
                if( $map['start'] == $map['end'] )
                    $mapsText[] = (string)$map['start'];
                else
                    $mapsText[] = $map['start'].'-'.$map['end'];
            }

            $returnText = PH::list_to_string($mapsText);
        }

        return $returnText;
    }

    /**
     * @return string
     */
    public function &udpMappingToText()
    {
        $returnText = '';

        if( count($this->udpPortMap) != 0 )
        {
            $mapsText = Array();
            foreach( $this->udpPortMap as &$map )
            {
                if( $map['start'] == $map['end'] )
                    $mapsText[] = (string)$map['start'];
                else
                    $mapsText[] = $map['start'].'-'.$map['end'];
            }

            $returnText = PH::list_to_string($mapsText);
        }

        return $returnText;
    }

    /**
     * @return bool
     */
    public function hasTcpMappings()
    {
        return count($this->tcpPortMap) > 0;
    }

    /**
     * @return bool
     */
    public function hasUdpMappings()
    {
        return count($this->udpPortMap) > 0;
    }

    /**
     * @param ServiceDstPortMapping $other
     * @return bool
     */
    public function equals( ServiceDstPortMapping $other )
    {
        if( !$this->tcpMappingIsSame($other) )
            return false;

        return $this->udpMappingIsSame($other);
    }

    static private function _mapsAreSame(&$map1, &$map2)
    {
        if(count($map1) != count($map2) )
            return false;

        $keys1 = array_keys($map1);
        $keys2 = array_keys($map2);

        for($i=0; $i<count($keys1); $i++)
        {
            if( $map1[$keys1[$i]]['start'] != $map2[$keys2[$i]]['start'] )
                return false;
            if( $map1[$keys1[$i]]['end'] != $map2[$keys2[$i]]['end'] )
                return false;
        }

        return true;
    }


    /**
     * @param ServiceDstPortMapping $other
     * @return bool
     */
    public function tcpMappingIsSame(ServiceDstPortMapping $other)
    {
        return ServiceDstPortMapping::_mapsAreSame($this->tcpPortMap, $other->tcpPortMap);
    }

    /**
     * @param ServiceDstPortMapping $other
     * @return bool
     */
    public function udpMappingIsSame(ServiceDstPortMapping $other)
    {
        return ServiceDstPortMapping::_mapsAreSame($this->udpPortMap, $other->udpPortMap);
    }

    /**
     * @return string
     */
    public function mappingToText()
    {
        $returnText = '';

        if( $this->hasTcpMappings() )
            $returnText .= 'tcp/'.$this->tcpMappingToText();

        if( $this->hasTcpMappings() && $this->hasUdpMappings() )
            $returnText .= ' ';

        if( $this->hasUdpMappings() )
            $returnText .= 'udp/'.$this->udpMappingToText();

        return $returnText;
    }
}

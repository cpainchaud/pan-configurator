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

class cidr
{
    // convert cidr to netmask
    // e.g. 21 = 255.255.248.0
    static public function cidr2netmask($cidr)
    {
        $bin = '';

        for( $i = 1; $i <= 32; $i++ )
            $bin .= $cidr >= $i ? '1' : '0';

        $netmask = long2ip(bindec($bin));

        if ( $netmask == "0.0.0.0")
            return false;

        return $netmask;
    }

    // get network address from cidr subnet
    // e.g. 10.0.2.56/21 = 10.0.0.0
    static public function cidr2network($ip, $cidr)
    {
        $network = long2ip((ip2long($ip)) & ((-1 << (32 - (int)$cidr))));

        return $network;
    }

    // convert netmask to cidr
    // e.g. 255.255.255.128 = 25
    static public function netmask2cidr($netmask)
    {
        $bits = 0;
        $netmask = explode(".", $netmask);

        foreach($netmask as $octect)
            $bits += strlen(str_replace("0", "", decbin($octect)));

        return $bits;
    }

    /**
     * @param int $start
     * @param int $end
     * @return bool|int[] FALSE if start/end do not match a network/mask. Otherwise : Array( 'network' => '10.0.0.0', 'mask' => 8, 'string' => '10.0.0.0/8')
     */
    static public function range2network($start,$end)
    {
        if( is_string($start) )
            derr("'start' cannot be a string");
        if( is_string($end) )
            derr("'end' cannot be a string");

        $diff = $end - $start + 1;

        $int2pow = Array();

        for($i=0; $i<32; $i++)
            $int2pow[pow(2, $i)] = $i;

        if( !isset($int2pow[$diff]) )
            return false;

        $netmask = 32 - $int2pow[$diff];

        $string  = long2ip($start).'/'.$netmask;

        $tmp = self::stringToStartEnd($string);

        if( $tmp['start'] != $start )
            return false;

        if( $tmp['end'] != $end )
            return false;

        return Array('network' => $start, 'mask' => $netmask, 'string' => $string );
    }

    /**
     * @param int $start    e.g. 2839055104 [169.56.139.0]
     * @param int $end      e.g. 2839056512 [169.56.144.128]
     * @return bool|int[] Array( '2839055104m24' => Array( 'network' => '2839055104', 'mask' => '24', 'string' => 169.56.139.0/24' )
     *      '2839055360m22' => Array( 'network' => '2839055360', 'mask' => '22', 'string' => 169.56.140.0/22' )
     *      '2839056384m25' => Array( 'network' => '2839056384', 'mask' => '25', 'string' => '169.56.144.0/25')
     *      '2839056512m32' => Array( 'network' => '2839056512', 'mask' => '32', 'string' => '169.56.144.128/32'))
     */
    static public function range2network_all($start,$end)
    {
        if( is_string($start) )
            derr("'start' cannot be a string");
        if( is_string($end) )
            derr("'end' cannot be a string");

        $diff = $end - $start + 1;
        $int2pow = Array();

        for( $i = 0; $i < 32; $i++ )
            $int2pow[pow(2, $i)] = $i;

        $networks = array();

        $netmask = 0;
        $netmask_id = 0;
        if( !isset($int2pow[$diff]) )
        {
            foreach( $int2pow as $id => $check_mask )
            {
                if( $id > $diff )
                {
                    $netmask = 32 - $check_mask;
                    $netmask_id = $id;
                    break;
                }
            }
            $string = long2ip($start) . '/' . $netmask;
            $tmp = self::stringToStartEnd($string);

            if( ($tmp['start'] != $start) || ($tmp['end'] != $end) )
            {
                $netmask_new = $netmask + 1;
                $checkstring = $start;

                if( ($tmp['start'] === $start) && ($tmp['end'] <= $end) )
                {
                    $string = long2ip($start) . '/' . $netmask;
                    $networks[$start."m".$netmask] = Array('network' => $start, 'mask' => $netmask, 'string' => $string );
                    $checkstring = $tmp['end'] + 1;
                }

                $end_of_start = FALSE;
                do
                {
                    $string = long2ip($checkstring) . '/' . $netmask_new;
                    $tmp = self::stringToStartEnd($string);
                    $checkstring_start = $checkstring;

                    if( ($tmp['start'] < $start) || ($tmp['end'] > $end) )
                    {
                        $netmask_new++;

                        if( $tmp['start'] === $start )
                        {
                            $checkstring = $tmp['start'];
                            $checkstring_start = $checkstring;
                        }
                    }
                    elseif( (($tmp['start'] === $start) && ($tmp['end'] <= $end)) || ($tmp['start'] === $checkstring && $tmp['end'] <= $end) )
                    {
                        $string = long2ip($checkstring) . '/' . $netmask_new;
                        $networks[$checkstring."m".$netmask_new] = Array('network' => $checkstring, 'mask' => $netmask_new, 'string' => $string );
                        $checkstring_start = $checkstring;
                        $checkstring = $tmp['end'] + 1;

                        $netmask_tmp = $netmask_id/2;
                        $netmask_new = 32-$int2pow[$netmask_tmp];
                    }

                    if( $end_of_start === FALSE )
                    {
                        if( ($tmp['start'] !== $start) )
                            $go = TRUE;
                        elseif( $tmp['end'] > $end )
                            $go = TRUE;
                        else
                        {
                            $end_of_start = TRUE;
                            $go = TRUE;
                            $netmask_new = $netmask;
                        }
                    }
                    else
                    {
                        if( ($tmp['end'] !== $end) )
                            $go = TRUE;
                        elseif( $tmp['start'] !== $checkstring_start )
                            $go = TRUE;
                        else
                            $go = FALSE;
                    }

                } while( $go );
            }
        }
        else{
            $netmask = 32 - $int2pow[$diff];
            $string = long2ip($start) . '/' . $netmask;
            $tmp = self::stringToStartEnd($string);

            if( ($tmp['start'] != $start) || ($tmp['end'] != $end) )
            {
                $netmask_new = $netmask + 1;

                if( $tmp['start'] != $start )
                    $checkstring = $start;
                elseif( $tmp['end'] != $end )
                    $checkstring = $tmp['end'] + 1;

                $end_of_start = FALSE;
                do
                {
                    $string = long2ip($checkstring) . '/' . $netmask_new;
                    $tmp = self::stringToStartEnd($string);
                    $checkstring_start = $checkstring;#not needed yet

                    if( $tmp['start'] < $start )
                    {
                        $netmask_new++;
                        $checkstring = $start;
                    }
                    else if( $tmp['end'] > $end )
                    {
                        $netmask_new++;
                        $checkstring = $tmp['start'];
                    }
                    else
                    {
                        $string = long2ip($checkstring) . '/' . $netmask_new;
                        $networks[$checkstring."m".$netmask_new] = Array('network' => $checkstring, 'mask' => $netmask_new, 'string' => $string );
                        $checkstring_start = $checkstring;#not needed yet
                        $checkstring = $tmp['end'] + 1;
                        $netmask_new = $netmask-1;
                    }

                    if( $end_of_start === FALSE )
                    {
                        if($tmp['start'] < $start)
                            $go = TRUE;
                        else
                        {
                            $end_of_start = TRUE;
                            $go = TRUE;
                            $netmask_new = $netmask;
                        }
                    }
                    else
                    {
                        if( ($tmp['end'] !== $end) )
                            $go = TRUE;
                        else
                            $go = FALSE;
                    }

                } while( $go );
            }
            else
            {
                $string = long2ip($start) . '/' . $netmask;
                $networks[$start."m".$netmask] = Array('network' => $start, 'mask' => $netmask, 'string' => $string );
            }
        }
        return $networks;
    }

    // is ip in subnet
    // e.g. is 10.5.21.30 in 10.5.16.0/20 == true
    //      is 192.168.50.2 in 192.168.30.0/23 == false
    static public function cidr_match($ip, $network, $cidr)
    {
        if ((ip2long($ip) & ~((1 << (32 - $cidr)) - 1) ) == ip2long($network))
        {
            return true;
        }

        return false;
    }

    /**
     * return 0 if not match, 1 if $sub is included in $ref, 2 if $sub is partially matched by $ref.
     * @param string|int[] $sub ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @param string|int[] $ref
     * @return int
     */
    static public function netMatch( $sub, $ref)
    {
        if( is_array($sub) )
        {
            $subNetwork = $sub['start'];
            $subBroadcast = $sub['end'];
        }
        else
        {
            $res = cidr::stringToStartEnd($sub);
            $subNetwork = $res['start'];
            $subBroadcast = $res['end'];
        }

        if( is_array($ref) )
        {
            $refNetwork = $ref['start'];
            $refBroadcast = $ref['end'];
        }
        else
        {
            $res = cidr::stringToStartEnd($ref);
            $refNetwork = $res['start'];
            $refBroadcast = $res['end'];
        }

        if( $subNetwork >= $refNetwork && $subBroadcast <= $refBroadcast )
        {
            //print "sub $sub is included in $ref\n";
            return 1;
        }
        if( $subNetwork >= $refNetwork &&  $subNetwork <= $refBroadcast ||
            $subBroadcast >= $refNetwork && $subBroadcast <= $refBroadcast ||
            $subNetwork <= $refNetwork && $subBroadcast >= $refBroadcast )
        {
            return 2;
        }

        return 0;
    }

    static public function &stringToStartEnd($value)
    {
        $result = Array();

        $ex = explode('-', $value);
        if( count($ex) == 2 )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[0]}' is not a valid IP");

            if( filter_var($ex[1], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[1]}' is not a valid IP");

            $result['start'] = ip2long($ex[0]);
            $result['end'] = ip2long($ex[1]);
            return $result;
        }


        $ex = explode('/', $value);
        if( count($ex) > 1 && $ex[1] != '32')
        {
            //$netmask = cidr::cidr2netmask($ex[0]);
            if( $ex[1] < 0 || $ex[1] > 32 )
                derr("invalid netmask in value {$value}");

            if( filter_var($ex[0], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[0]}' is not a valid IP");

            $bmask = 0;
            for($i=1; $i<= (32-$ex[1]); $i++)
                $bmask += pow(2, $i-1);

            $subNetwork = ip2long($ex[0]) & ((-1 << (32 - (int)$ex[1])) );
            $subBroadcast = ip2long($ex[0]) | $bmask;
        }
        elseif( count($ex) > 1 && $ex[1] == '32' )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[0]}' is not a valid IP");
            $subNetwork = ip2long($ex[0]);
            $subBroadcast = $subNetwork;
        }
        else
        {
            if( filter_var($value, FILTER_VALIDATE_IP) === false )
                derr("'{$value}' is not a valid IP");

            $subNetwork = ip2long($value);
            $subBroadcast = ip2long($value);
        }

        $result['start'] = $subNetwork;
        $result['end'] = $subBroadcast;

        return $result;
    }


}
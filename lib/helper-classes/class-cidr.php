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

    private static $_int2pow = null;
    private static $_cidr2maskInt = null;

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

        if( self::$_int2pow === null )
        {
            self::$_int2pow = Array();
            for($i=0; $i<32; $i++)
                self::$_int2pow[pow(2, $i)] = $i;
        }
        if( self::$_cidr2maskInt === null )
        {
            self::$_cidr2maskInt= Array();
            self::$_cidr2maskInt[0] = 0;
            self::$_cidr2maskInt[32] = 4294967295;
            for($i=1; $i<=31; $i++)
                self::$_cidr2maskInt[$i] = self::$_cidr2maskInt[$i-1] + pow(2, 32-$i);
        }

        if( !isset(self::$_int2pow[$diff]) )
            return false;

        $netmask = 32 - self::$_int2pow[$diff];
        $calculatedNetworkStart = $start & self::$_cidr2maskInt[$netmask];

        if( $start != $calculatedNetworkStart )
            return false;

        return Array('network' => $start, 'mask' => $netmask, 'string' => long2ip($start).'/'.$netmask );
    }


    // is ip in subnet
    // e.g. is 10.5.21.30 in 10.5.16.0/20 == true
    //      is 192.168.50.2 in 192.168.30.0/23 == false
    /**
     * @param string $ip
     * @param string $network
     * @param int $cidr
     * @return bool
     */
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


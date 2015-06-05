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
            //print "sub $sub is partially included in $ref :  ".long2ip($subNetwork)."/".long2ip($subBroadcast)." vs ".long2ip($refNetwork)."/".long2ip($refBroadcast)."\n";
            //print "sub $sub is partially included in $ref :  ".$refNetwork."/".$subBroadcast."/".$refBroadcast."\n";
            return 2;
        }

        //print "sub $sub is not matching $ref :  ".long2ip($subNetwork)."/".long2ip($subBroadcast)." vs ".long2ip($refNetwork)."/".long2ip($refBroadcast)."\n";
        return 0;
    }

    static public function & stringToStartEnd($value)
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
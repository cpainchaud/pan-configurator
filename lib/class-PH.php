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

class PH
{

    public static $UseDomXML = false;

    /**
     * @var null|mixed[]
     */
    public static $args = null;

    /**
     * enables faster but very experimental DomXML support in Pan Configurator
     */
    static public function enableDomXMLSupport()
    {
        self::$UseDomXML = true;
        print "\n\nWARNING, Alternative Xml Lib (DOM XML) support is experimental, use at your own risk\n\n";
    }


    /**
     * @param bool $yes
     */
    public static function enableAlternativeXmlLib($yes)
    {

    }

    public static function processCliArgs()
    {
        global $argv;

        PH::$args = Array();

        $first = true;

        foreach( $argv as &$arg )
        {
            if( $first )
            {
                $first = false;
                continue;
            }
            $nameExplode = explode('=',$arg, 2);
            if( count($nameExplode) != 2 )
                $value = true;
            else
                $value = $nameExplode[1];

            $nameExplode[0] = strtolower($nameExplode[0]);
            $nameExplode[0] = str_ireplace( '-', '', $nameExplode[0]);

            if( isset(PH::$args[$nameExplode[0]]) )
                derr("argument '".PH::$args[$nameExplode[0]]."' was input twice in command line");

            PH::$args[$nameExplode[0]] = $value;
        }

        //print_r(PH::$args);
    }

    /**
     * @param $str
     * @param bool $checkFileExists
     * @return string[]
     */
    public static function &processIOMethod($str, $checkFileExists)
    {
        $ret = Array('status' => 'fail' );

        $pos = strpos($str, 'api://');
        if( $pos !== false)
        {
            PanAPIConnector::loadConnectorsFromUserHome();
            $host = substr($str, strlen('api://') );
            $hostExplode = explode('@', $host);
            if( count($hostExplode) == 1 )
            {
                $connector = PanAPIConnector::findOrCreateConnectorFromHost($host);
            }
            else
            {
                $connector = PanAPIConnector::findOrCreateConnectorFromHost($hostExplode[1]);
                $connector->setType('panos-via-panorama', $hostExplode[0]);
            }

            $ret['status'] = 'ok';
            $ret['type'] = 'api';
            $ret['connector'] = $connector;

        }
        else
        {
            //assuming it's a file
            if( $checkFileExists && !file_exists($str) )
            {
                $ret['msg'] = 'file "'.$str.'" does not exist';
                return $ret;
            }
            $ret['status'] = 'ok';
            $ret['type'] = 'file';
            $ret['filename'] = $str;
        }

        return $ret;

    }

    /**
     * @param string $text
     * @return int
     */
    static public function versionFromString($text)
    {
        if( $text === null )
            derr('null is not supported');

        if( !is_string($text) )
            derr('only string is supported as input');


        $explode = explode('.',$text);
        if( count($explode) != 3 )
            derr('unsupported versioning: '.$text );

        $ret = $explode[0]*10 + $explode[1];

        return $ret;
    }

    /**
     * @param string|ReferenceableObject[] $array
     * @return string
     */
    static public function &list_to_string(&$array)
    {
        $ret = '';
        $first = true;

        foreach($array as &$el)
        {
            if( $first )
            {
                $first = false;
                if( is_string($el) )
                    $ret .= $el;
                else
                    $ret .= $el->name();
            }
            else
            {
                if( is_string($el) )
                    $ret .= ','.$el;
                else
                    $ret .= ','.$el->name();
            }

        }

        return $ret;

    }

    static public function &boldText($msg)
    {
        $term = getenv('TERM');

        if( $term === false || strpos($term, 'xterm') === false )
        {
            //if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
            //    $msg = "\027[1;37m".$msg."\027[37m";
        }
        else
            $msg = "\033[1m".$msg."\033[0m";

        return $msg;
    }

}

foreach( $argv as $argIndex => &$arg )
{
    if( $arg == 'shadow-usedomxml')
    {
        PH::enableDomXMLSupport();
        unset($argv[$argIndex]);
        unset($argIndex);
        unset($arg);
        $argc--;
        break;
    }
}
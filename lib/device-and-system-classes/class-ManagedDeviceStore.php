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
/**
 * Class ManagedDeviceStore
 * @property ManagedDevice[] $o
 * @property PanoramaConf $owner
 * @method ManagedDevice[] getAll()
 */
class ManagedDeviceStore extends ObjStore
{
    /** @var  PanoramaConf */
    public $owner;

    /** @var null|TagStore */
    protected $parentCentralStore = null;

    public static $childn = 'ManagedDevice';


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = Array();
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->owner->managedFirewallsSerials = $this->get_serial_from_xml( $xml, true );

    }

    public function get_serial_from_xml( DOMElement $xml, $add_firewall = false )
    {
        $tmp_managedFirewallsSerials = array();

        $tmp = DH::findFirstElementOrCreate('devices', $xml);

        foreach( $tmp->childNodes as $serial )
        {
            if( $serial->nodeType != 1 )
                continue;
            $s = DH::findAttribute('name', $serial);
            if( $s === FALSE )
                derr('no serial found');

            if( $add_firewall )
            {
                $tmp_obj = new ManagedDevice(  $s, $this );
                $this->add( $tmp_obj );
            }


            $tmp_managedFirewallsSerials[$s] = $s;
        }
        return $tmp_managedFirewallsSerials;
    }

    /**
     * @param $serial
     * @param null $ref
     * @param bool $nested
     * @return null|ManagedDevice
     */
    public function find($serial, $ref = null, $nested = TRUE)
    {
        $f = $this->findByName($serial, $ref);

        if( $f !== null )
            return $f;

        return null;
    }
}
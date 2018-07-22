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
 * Class VirtualWireStore
 * @property $o VirutalWire[]
 */
class VirtualWireStore extends ObjStore
{

    /** @var null|PANConf */
    public $owner;

    protected $fastMemToIndex=null;
    protected $fastNameToIndex=null;

    public static $childn = 'VirtualWire';

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return VirtualWire[]
     */
    public function virtualWires()
    {
        return $this->o;
    }

    /**
     * @param $vwName string
     * @return null|VirtualWire
     */
    public function findVirtualWire( $vwName )
    {
        return $this->findByName( $vwName );
    }


    /**
     * Creates a new VirtualWire in this store. It will be placed at the end of the list.
     * @param string $name name of the new VirtualWire
     * @return VirtualWire
     */
    public function newVirtualWire($name)
    {
        $virtualWire = new VirtualWire( $name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, VirtualWire::$templatexml);

        $virtualWire->load_from_domxml($xmlElement);

        $virtualWire->owner = null;
        $virtualWire->setName($name);

        $this->addVirtualWire( $virtualWire );

        return $virtualWire;
    }

    public function API_newVirtualWire($name)
    {
        $newvw = $this->newVirtualWire($name);

        $con = findConnectorOrDie($this);
        //$xpath = $newvw->getXPath();
        $xpath = $this->getEthernetIfStoreXPath();
        $con->sendSetRequest($xpath, "<entry name='{$newvw->name()}'/>", true );

        return $newvw;
    }


    /**
     * @param VirtualWire $virtualWire
     * @return bool
     */
    public function addVirtualWire($virtualWire )
    {
        if( !is_object($virtualWire) )
            derr('this function only accepts VirtualWire class objects');

        if( $virtualWire->owner !== null )
            derr('Trying to add a VirtualWire that has a owner already !');


        $ser = spl_object_hash($virtualWire);

        if (!isset($this->fastMemToIndex[$ser]))
        {
            $virtualWire->owner = $this;

            $this->fastMemToIndex[$ser] = $virtualWire;
            $this->fastNameToIndex[$virtualWire->name()] = $virtualWire;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($virtualWire->xmlroot);

            return true;
        } else
            derr('You cannot add a VirtualWire that is already here :)');

        return false;
    }

    /**
     * @param EthernetInterface $s
     * @return bool
     */
    public function API_addVirtualWire( $s )
    {
        $ret = $this->addVirtualWire($s);

        if( $ret )
        {
            $con = findConnectorOrDie($this);

            $xpath = $this->getEthernetIfStoreXPath();

            $con->sendSetRequest($xpath, "<entry name='{$s->name()}'/>");
        }

        return $ret;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('virtual-wire', $xml);
        }
    }

    private function &getBaseXPath()
    {

        $str = "";
        /*
                if( $this->owner->owner->isTemplate() )
                    $str .= $this->owner->owner->getXPath();
                elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
                    $str = '/config/shared';
                else
                    derr('unsupported');
        */

        //TODO: intermediate solution
        $str .= '/config/devices/entry/network';

        return $str;
    }

    public function &getEthernetIfStoreXPath()
    {
        $path = $this->getBaseXPath().'/virtual-wire';
        return $path;
    }

}